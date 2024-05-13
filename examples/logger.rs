use std::{
    convert::Infallible,
    net::{IpAddr, Ipv4Addr},
};

use bytes::Bytes;
use tempo::{
    handler::{HttpHandler, RequestOrResponse, WebsocketHandler},
    http_body_util::combinators::BoxBody,
    hyper::{Request, Response},
    utils::{HttpSession, WebSocketSession},
    Tempo,
};
use tokio_tungstenite::tungstenite::Message;
use tracing::debug;
use tracing_subscriber::EnvFilter;

#[derive(Clone)]
pub struct Logger;

impl HttpHandler for Logger {
    async fn on_request(
        &mut self,
        _session: &HttpSession,
        req: Request<BoxBody<Bytes, Infallible>>,
    ) -> RequestOrResponse {
        debug!("{:?}", req);
        RequestOrResponse::Request(req)
    }

    async fn on_response(
        &mut self,
        _session: &HttpSession,
        res: Response<BoxBody<Bytes, Infallible>>,
    ) -> Response<BoxBody<Bytes, Infallible>> {
        debug!("{:?}", res);
        res
    }
}

impl WebsocketHandler for Logger {
    async fn on_start(&mut self, _session: &HttpSession, req: Request<()>) -> Request<()> {
        debug!("{:?}", req);
        req
    }

    async fn on_client_message(
        &mut self,
        _session: &WebSocketSession,
        message: Message,
    ) -> Option<Message> {
        debug!("{:?}", message);
        Some(message)
    }

    async fn on_server_message(
        &mut self,
        _session: &WebSocketSession,
        message: Message,
    ) -> Option<Message> {
        debug!("{:?}", message);
        Some(message)
    }

    async fn on_close(&mut self, _session: &WebSocketSession) {}
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    Tempo::builder()
        .http_handler(Logger)
        .websocket_handler(Logger)
        .host(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)))
        .port(1234)
        // .authorization(Authorization {
        //     username: "khanhnt".to_string(),
        //     password: "123456".to_string(),
        // })
        .build()
        .unwrap()
        .start()
        .await;
    Ok(())
}
