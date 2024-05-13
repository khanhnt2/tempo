use bytes::Bytes;
use futures::Future;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::{
    body::Incoming,
    header::{self, Entry},
    http::uri::{Authority, Scheme, Uri},
    rt::{Read, Write},
    service::{service_fn, Service},
    Method, Request, Response, StatusCode, Version,
};
use hyper_util::{
    client::legacy::{connect::Connect, Client},
    rt::{TokioExecutor, TokioIo},
    server::conn::auto,
};
use std::{convert::Infallible, pin::Pin, str::FromStr, sync::Arc};
use tokio::{io::AsyncReadExt, net::TcpStream};
use tracing::*;

use crate::{
    builder::Authorization,
    certificate::CertificateAuthority,
    handler::{HttpHandler, RequestOrResponse, WebsocketHandler},
    rewind::Rewind,
    utils::{bad_request, badgateway_error, empty, HttpSession, SupportedProtocol},
};

#[derive(Clone)]
pub(crate) struct InternalHandler<H, W, C>
where
    H: HttpHandler,
    W: WebsocketHandler,
    C: Connect,
{
    session: HttpSession,
    ca: Arc<CertificateAuthority>,
    http_client: Client<C, BoxBody<Bytes, Infallible>>,
    http_handler: H,
    websocket_handler: W,
    auth: Option<Authorization>,
}

impl<H, W, C> Service<Request<Incoming>> for InternalHandler<H, W, C>
where
    H: HttpHandler,
    W: WebsocketHandler,
    C: Connect + Clone + Send + Sync + 'static,
{
    type Response = Response<BoxBody<Bytes, Infallible>>;
    type Error = hyper::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, mut req: Request<Incoming>) -> Self::Future {
        // if the proxy enables authorization
        if let Some(auth) = &self.auth {
            if let Some(value) = req.headers().get(header::PROXY_AUTHORIZATION) {
                if let Ok(value) = value.to_str() {
                    if let Ok(creds) = http_auth_basic::Credentials::from_str(value) {
                        if creds.user_id == auth.username && creds.password == auth.password {
                            req.headers_mut().remove(header::PROXY_AUTHORIZATION);
                            return Box::pin(self.clone().proxy(req));
                        }
                    }
                }
            }
            Box::pin(async {
                Ok(Response::builder()
                    .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                    .header(
                        header::PROXY_AUTHENTICATE,
                        "Basic \"Access to the internal site\"",
                    )
                    .body(empty().boxed())
                    .expect("Failed to build PROXY_AUTHENTICATION_REQUIRED response"))
            })
        } else {
            Box::pin(self.clone().proxy(req))
        }
    }
}

impl<H, W, C> InternalHandler<H, W, C>
where
    H: HttpHandler,
    W: WebsocketHandler,
    C: Connect + Clone + Send + Sync + 'static,
{
    pub(crate) fn new(
        session: HttpSession,
        ca: Arc<CertificateAuthority>,
        auth: Option<Authorization>,
        http_client: Client<C, BoxBody<Bytes, Infallible>>,
        http_handler: H,
        websocket_handler: W,
    ) -> Self {
        Self {
            session,
            ca,
            http_client,
            auth,
            http_handler,
            websocket_handler,
        }
    }

    #[instrument(
        skip_all,
        fields(
            version = ?req.version(),
            method = %req.method(),
            uri = %req.uri()
        )
    )]
    async fn proxy(
        mut self,
        req: Request<Incoming>,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, hyper::Error> {
        let (parts, body) = req.into_parts();
        let body = match body.collect().await {
            Ok(data) => data.to_bytes(),
            Err(err) => {
                return Ok(bad_request(format!(
                    "Failed to read request body: {:#?}",
                    err
                )))
            }
        };

        let req = Request::from_parts(parts, Full::new(body).boxed());

        let req = match self
            .http_handler
            .on_request(&self.session, req)
            .instrument(info_span!("on_request"))
            .await
        {
            RequestOrResponse::Request(req) => req,
            RequestOrResponse::Response(res) => return Ok(res),
        };
        if req.method() == Method::CONNECT {
            Ok(self.process_connect(req))
        } else if hyper_tungstenite::is_upgrade_request(&req) {
            Ok(self.upgrade_websocket(req).await)
        } else {
            let (mut parts, body) = req.into_parts();
            parts.version = Version::HTTP_11;
            // Hyper will automatically add a Host header if needed.
            parts.headers.remove(hyper::header::HOST);
            // HTTP/2 supports multiple cookie headers, but HTTP/1.x only supports one.
            if let Entry::Occupied(mut cookies) = parts.headers.entry(hyper::header::COOKIE) {
                let joined_cookies = bstr::join(b"; ", cookies.iter());
                cookies.insert(joined_cookies.try_into().expect("Failed to join cookies"));
            }

            let req = Request::from_parts(parts, body);

            match self.http_client.request(req).await {
                Ok(res) => {
                    let (parts, body) = res.into_parts();
                    let body = match body.collect().await {
                        Ok(data) => data.to_bytes(),
                        Err(err) => {
                            return Ok(badgateway_error(format!(
                                "Failed to read upstream response: {:#?}",
                                err
                            )))
                        }
                    };

                    let res = Response::from_parts(parts, Full::new(body).boxed());
                    Ok(self
                        .http_handler
                        .on_response(&self.session, res)
                        .instrument(info_span!("on_response"))
                        .await)
                }
                Err(err) => {
                    error!("Failed to send a request: {err}");
                    return Ok(self
                        .http_handler
                        .on_error(&self.session, err)
                        .instrument(info_span!("on_error"))
                        .await);
                }
            }
        }
    }

    fn process_connect(
        self,
        mut req: Request<BoxBody<Bytes, Infallible>>,
    ) -> Response<BoxBody<Bytes, Infallible>> {
        match req.uri().authority().cloned() {
            Some(authority) => {
                let fut = async move {
                    match hyper::upgrade::on(&mut req).await {
                        Ok(upgraded) => {
                            let mut upgraded = TokioIo::new(upgraded);
                            let mut buffer = [0; 4];
                            let bytes_read = match upgraded.read(&mut buffer).await {
                                Ok(bytes) => bytes,
                                Err(e) => {
                                    error!("Failed to read from upgraded connection: {e}");
                                    return;
                                }
                            };
                            let mut upgraded = Rewind::new_buffered(
                                upgraded,
                                Bytes::copy_from_slice(buffer[..bytes_read].as_ref()),
                            );

                            let protocol = SupportedProtocol::from_bytes(&buffer);
                            match (
                                self.http_handler.should_intercept(&self.session, &req),
                                protocol,
                            ) {
                                (true, SupportedProtocol::Tls) => {
                                    let tls_acceptor =
                                        self.ca.get_tls_acceptor(authority.host()).await;
                                    let stream = match tls_acceptor.accept(upgraded).await {
                                        Ok(stream) => stream,
                                        Err(e) => {
                                            error!("Failed to establish TLS: {e}");
                                            return;
                                        }
                                    };
                                    if let Err(e) = self
                                        .serve_stream(
                                            TokioIo::new(stream),
                                            Scheme::HTTPS,
                                            authority,
                                        )
                                        .await
                                    {
                                        if !e
                                            .to_string()
                                            .starts_with("error shutting down connection")
                                        {
                                            error!("HTTPS connection error: {e}");
                                        }
                                    }
                                }
                                (true, SupportedProtocol::WebSocket) => {
                                    if let Err(e) =
                                        self.serve_stream(upgraded, Scheme::HTTP, authority).await
                                    {
                                        error!("WebSocket connection error: {e}");
                                    }
                                }
                                (_, SupportedProtocol::Unknown) | (false, _) => {
                                    if protocol == SupportedProtocol::Unknown {
                                        warn!("Unsupport protocol, read '{:02X?}' from upgraded connection", &buffer[..bytes_read]);
                                    }
                                    let mut server =
                                        match TcpStream::connect(authority.as_ref()).await {
                                            Ok(server) => server,
                                            Err(e) => {
                                                error!("Failed to connect to {authority}: {e}");
                                                return;
                                            }
                                        };

                                    if let Err(e) =
                                        tokio::io::copy_bidirectional(&mut upgraded, &mut server)
                                            .await
                                    {
                                        error!("Failed to tunnel to {authority}: {e}");
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            error!("Upgrade error: {e}");
                        }
                    };
                };
                tokio::spawn(fut.instrument(info_span!("process_connect")));
                Response::new(empty())
            }
            None => bad_request("Request doesn't have URI !?!".into()),
        }
    }

    async fn serve_stream<I>(
        &self,
        stream: I,
        scheme: Scheme,
        authority: Authority,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        I: Unpin + Send + Read + Write + 'static,
    {
        let service = service_fn(|mut req| {
            if req.version() == hyper::Version::HTTP_10 || req.version() == hyper::Version::HTTP_11
            {
                let (mut parts, body) = req.into_parts();

                parts.uri = {
                    let mut parts = parts.uri.into_parts();
                    parts.scheme = Some(scheme.clone());
                    parts.authority = Some(authority.clone());
                    Uri::from_parts(parts).expect("Failed to build URI")
                };

                req = Request::from_parts(parts, body);
            };
            self.clone().proxy(req)
        });
        let mut builder = auto::Builder::new(TokioExecutor::new());
        builder
            .http1()
            .preserve_header_case(true)
            .title_case_headers(true);
        builder.http2().enable_connect_protocol();
        builder
            .serve_connection_with_upgrades(stream, service)
            .await
    }

    #[instrument(skip_all, name = "websocket")]
    async fn upgrade_websocket(
        mut self,
        req: Request<BoxBody<Bytes, Infallible>>,
    ) -> Response<BoxBody<Bytes, Infallible>> {
        let mut req = {
            let (mut parts, _) = req.into_parts();
            parts.uri = {
                let mut parts = parts.uri.into_parts();
                parts.scheme = if parts.scheme.unwrap_or(Scheme::HTTP) == Scheme::HTTP {
                    Some("ws".try_into().expect("Failed to convert WS scheme"))
                } else {
                    Some("wss".try_into().expect("Failed to convert WSS scheme"))
                };

                match Uri::from_parts(parts) {
                    Ok(uri) => uri,
                    Err(err) => {
                        error!("Failed to construct an URI {err}");
                        return bad_request(format!("Failed to construct an URI {:#?}", err));
                    }
                }
            };
            // Currently, tungstenite hasn't supported permessage-deflate yet
            // So we have to disable the extensions to read plain message
            parts
                .headers
                .remove(hyper::header::SEC_WEBSOCKET_EXTENSIONS);
            Request::from_parts(parts, ())
        };

        match hyper_tungstenite::upgrade(&mut req, None) {
            Ok((res, websocket)) => {
                let fut = async move {
                    match websocket.await {
                        Ok(client_socket) => {
                            match tokio_tungstenite::connect_async(
                                self.websocket_handler
                                    .on_start(&self.session, req)
                                    .instrument(info_span!("on_start"))
                                    .await,
                            )
                            .await
                            {
                                Ok((server_socket, _)) => {
                                    self.websocket_handler
                                        .process_bidirection(
                                            &self.session.into(),
                                            client_socket,
                                            server_socket,
                                        )
                                        .await;
                                }
                                Err(err) => {
                                    error!("Failed to connect to Websocket: {err}");
                                }
                            }
                        }
                        Err(e) => {
                            error!("Failed to create WebSocketStream: {e}");
                        }
                    }
                };

                tokio::task::spawn(fut.in_current_span());
                let (parts, body) = res.into_parts();
                Response::from_parts(parts, body.boxed())
            }
            Err(err) => {
                error!("Failed to upgrade to Websocket: {err}");
                bad_request(format!("{:#?}", err))
            }
        }
    }
}
