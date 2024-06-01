use bytes::Bytes;
use futures::{stream::FusedStream, Sink, SinkExt, Stream, StreamExt};
use http_body_util::combinators::BoxBody;
use hyper::{Request, Response};
use std::{convert::Infallible, future::Future};
use tokio_tungstenite::tungstenite::{self, Message};
use tracing::{error, info_span, Instrument};

use crate::utils::{internal_error, HttpSession, WebSocketSession};

pub enum RequestOrResponse {
    Request(Request<BoxBody<Bytes, Infallible>>),
    Response(Response<BoxBody<Bytes, Infallible>>),
}
pub trait HttpHandler: Clone + Send + Sync + 'static {
    fn should_intercept(
        &self,
        _session: &HttpSession,
        _req: &Request<BoxBody<Bytes, Infallible>>,
    ) -> bool {
        true
    }

    fn on_request(
        &mut self,
        _session: &HttpSession,
        req: Request<BoxBody<Bytes, Infallible>>,
    ) -> impl Future<Output = RequestOrResponse> + Send;

    fn on_response(
        &mut self,
        _session: &HttpSession,
        res: Response<BoxBody<Bytes, Infallible>>,
    ) -> impl Future<Output = Response<BoxBody<Bytes, Infallible>>> + Send;

    fn on_error(
        &mut self,
        _session: &HttpSession,
        err: hyper_util::client::legacy::Error,
    ) -> impl Future<Output = Response<BoxBody<Bytes, Infallible>>> + Send {
        async move { internal_error(format!("Failed to send a request: {:#?}", err)) }
    }
}

pub trait WebsocketHandler: Clone + Send + Sync + 'static {
    fn process_bidirection<C, S>(
        &mut self,
        session: &WebSocketSession,
        mut client: C,
        mut server: S,
    ) -> impl Future<Output = ()> + Send
    where
        C: Stream<Item = Result<Message, tungstenite::Error>>
            + Sink<Message, Error = tungstenite::Error>
            + FusedStream
            + Unpin
            + Send
            + 'static,
        S: Stream<Item = Result<Message, tungstenite::Error>>
            + Sink<Message, Error = tungstenite::Error>
            + FusedStream
            + Unpin
            + Send
            + 'static,
    {
        async move {
            loop {
                let is_close = tokio::select! {
                    option = client.next() => {
                        if let Some(Ok(message)) = option {
                            match self.on_client_message(session, message).instrument(info_span!("on_client_message")).await {
                                Some(message) => {
                                    match server.send(message).await {
                                        Err(err) => {
                                            match err {
                                                tungstenite::Error::ConnectionClosed => (),
                                                _ => error!("Failed to send the message to the server: {err}")
                                            };
                                            true
                                        },
                                        Ok(_) => client.is_terminated()
                                    }
                                },
                                None => false
                            }
                        } else if let Some(Err(err)) = option {
                            error!("Failed to read the message from the client: {err}");
                            true
                        } else {
                            true
                        }
                    },
                    option = server.next() => {
                        if let Some(Ok(message)) = option {
                            match self.on_server_message(session, message).instrument(info_span!("on_server_message")).await {
                                Some(message) => {
                                    match client.send(message).await {
                                        Err(err) => {
                                            match err {
                                                tungstenite::Error::ConnectionClosed => (),
                                                _ => error!("Failed to send the message to the client: {err}")
                                            };
                                            true
                                        },
                                        Ok(_) => server.is_terminated()
                                    }
                                },
                                None => false
                            }
                        } else if let Some(Err(err)) = option {
                            error!("Failed to read the message from the server: {err}");
                            true
                        } else {
                            true
                        }
                    }
                };
                if is_close {
                    self.on_close(session)
                        .instrument(info_span!("on_close"))
                        .await;
                    break;
                };
            }
        }
    }

    fn on_start(
        &mut self,
        _session: &HttpSession,
        req: Request<()>,
    ) -> impl Future<Output = Request<()>> + Send;

    fn on_client_message(
        &mut self,
        _session: &WebSocketSession,
        message: Message,
    ) -> impl Future<Output = Option<Message>> + Send;

    fn on_server_message(
        &mut self,
        _session: &WebSocketSession,
        message: Message,
    ) -> impl Future<Output = Option<Message>> + Send;

    fn on_close(&mut self, _session: &WebSocketSession) -> impl Future<Output = ()> + Send;
}
