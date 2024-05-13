use std::convert::Infallible;
use std::fs::File;
use std::io::{BufReader, Error};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
#[cfg(feature = "rust-tls")]
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
#[cfg(feature = "native-tls")]
use hyper_tls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use rustls_pemfile as pemfile;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::TcpListener;
use tracing::error;
use typed_builder::TypedBuilder;

use crate::certificate::CertificateAuthority;
use crate::handler::{HttpHandler, WebsocketHandler};
use crate::proxy::InternalHandler;
use crate::utils::HttpSession;

lazy_static! {
    static ref CLIENT_HTTP_KEEPALIVE: Duration = Duration::from_secs(60);
    static ref CLIENT_HTTP_TIMEOUT: Duration = Duration::from_secs(120);
    static ref CLIENT_HTTP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
}

pub struct Certificate {
    pub cert: String,
    pub key: String,
}

impl Default for Certificate {
    fn default() -> Self {
        Self {
            cert: "ca/ByteDeflect.cer".to_string(),
            key: "ca/ByteDeflect.key".to_string(),
        }
    }
}

#[derive(Clone)]
pub struct Authorization {
    pub username: String,
    pub password: String,
}

#[derive(TypedBuilder)]
#[builder(build_method(vis="", name=__build))]
pub struct Proxy<H, W>
where
    H: HttpHandler,
    W: WebsocketHandler,
{
    http_handler: H,
    websocket_handler: W,
    #[builder(default_code = r#"IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))"#)]
    host: IpAddr,
    #[builder(default = 1234)]
    port: u16,
    #[builder(default)]
    certificate: Certificate,
    #[builder(default, setter(strip_option))]
    authorization: Option<Authorization>,
}

#[allow(non_camel_case_types)]
impl<
        H,
        W,
        __host: ::typed_builder::Optional<IpAddr>,
        __port: ::typed_builder::Optional<u16>,
        __certificate: ::typed_builder::Optional<Certificate>,
        __authorization: ::typed_builder::Optional<Option<Authorization>>,
    > ProxyBuilder<H, W, ((H,), (W,), __host, __port, __certificate, __authorization)>
where
    H: HttpHandler,
    W: WebsocketHandler,
{
    pub fn build(self) -> Result<ProxyServer<H, W>, Error> {
        let this = self.__build();
        let address = SocketAddr::from((this.host, this.port));
        let cert = pemfile::certs(&mut BufReader::new(File::open(
            this.certificate.cert.clone(),
        )?))
        .next()
        .expect("Cannot find root CA")
        .expect("Failed to parse root CA");
        let private_key = pemfile::pkcs8_private_keys(&mut BufReader::new(File::open(
            this.certificate.key.clone(),
        )?))
        .next()
        .expect("Cannot find private key")
        .expect("Failed to parse private key");

        Ok(ProxyServer::new(
            address,
            cert,
            PrivateKeyDer::Pkcs8(private_key),
            this.authorization,
            this.http_handler,
            this.websocket_handler,
        ))
    }
}

#[non_exhaustive]
pub struct ProxyServer<H, W>
where
    H: HttpHandler,
    W: WebsocketHandler,
{
    address: SocketAddr,
    ca: Arc<CertificateAuthority>,
    auth: Option<Authorization>,
    http_handler: H,
    websocket_handler: W,
}

impl<H: HttpHandler, W: WebsocketHandler> ProxyServer<H, W> {
    fn new(
        address: SocketAddr,
        cert: CertificateDer<'static>,
        private_key: PrivateKeyDer<'static>,
        auth: Option<Authorization>,
        http_handler: H,
        websocket_handler: W,
    ) -> Self {
        Self {
            address,
            ca: Arc::new(CertificateAuthority::new(cert, private_key)),
            auth,
            http_handler,
            websocket_handler,
        }
    }

    fn new_http_client(&self) -> Client<HttpsConnector<HttpConnector>, BoxBody<Bytes, Infallible>> {
        let mut http = HttpConnector::new();
        http.set_keepalive(Some(*CLIENT_HTTP_KEEPALIVE));
        http.set_connect_timeout(Some(*CLIENT_HTTP_TIMEOUT));
        http.set_keepalive_interval(Some(*CLIENT_HTTP_KEEPALIVE_INTERVAL));
        http.enforce_http(false);
        #[cfg(feature = "rust-tls")]
        let https = HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_all_versions()
            .wrap_connector(http);
        #[cfg(feature = "native-tls")]
        let https = HttpsConnector::new_with_connector(http);

        Client::builder(TokioExecutor::new())
            .http1_preserve_header_case(true)
            .http1_title_case_headers(true)
            .build(https)
    }

    pub async fn start(self) {
        let listener = TcpListener::bind(self.address)
            .await
            .unwrap_or_else(|_| panic!("Cannot listen at {}", self.address));
        let http_client = self.new_http_client();

        loop {
            let (stream, client_addr) = match listener.accept().await {
                Ok((stream, client_addr)) => (stream, client_addr),
                Err(err) => {
                    error!("Failed to accept the connection: {err}");
                    tokio::task::yield_now().await;
                    continue;
                }
            };
            let io = TokioIo::new(stream);
            let handler = InternalHandler::new(
                HttpSession::new(client_addr),
                self.ca.clone(),
                self.auth.clone(),
                http_client.clone(),
                self.http_handler.clone(),
                self.websocket_handler.clone(),
            );

            tokio::spawn(async move {
                let mut builder = auto::Builder::new(TokioExecutor::new());
                builder
                    .http1()
                    .preserve_header_case(true)
                    .title_case_headers(true);
                builder.http2().enable_connect_protocol();

                if let Err(err) = builder.serve_connection_with_upgrades(io, handler).await {
                    error!("Failed to serve connection: {err}")
                }
            });
        }
    }
}
