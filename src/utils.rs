use std::{convert::Infallible, net::SocketAddr};

use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full, combinators::BoxBody};
use hyper::{Response, StatusCode};
use uuid::Uuid;

pub fn bad_request(err: String) -> Response<BoxBody<Bytes, Infallible>> {
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(Full::new(err.into()).boxed())
        .expect("Failed to build a response for a bad request")
}

pub fn internal_error(err: String) -> Response<BoxBody<Bytes, Infallible>> {
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .body(Full::new(err.into()).boxed())
        .expect("Failed to build a internal server error response")
}

pub fn badgateway_error(err: String) -> Response<BoxBody<Bytes, Infallible>> {
    Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .body(Full::new(err.into()).boxed())
        .expect("Failed to build a bad gateway response")
}

pub fn empty() -> BoxBody<Bytes, Infallible> {
    Empty::<Bytes>::new().boxed()
}

#[non_exhaustive]
#[derive(PartialEq, Copy, Clone)]
pub enum SupportedProtocol {
    Tls,
    WebSocket,
    Unknown,
}

impl SupportedProtocol {
    pub fn from_bytes(buffer: &[u8; 4]) -> Self {
        if buffer[..2] == *b"\x16\x03" && buffer[2] <= 0x3 {
            SupportedProtocol::Tls
        } else if buffer == &b"GET "[..] {
            SupportedProtocol::WebSocket
        } else {
            SupportedProtocol::Unknown
        }
    }
}

#[derive(Clone)]
pub struct HttpSession {
    pub id: Uuid,
    pub client: SocketAddr,
}

impl HttpSession {
    pub fn new(client: SocketAddr) -> Self {
        Self {
            id: Uuid::new_v4(),
            client,
        }
    }
}

pub struct WebSocketSession {
    pub id: Uuid,
}

impl WebSocketSession {
    pub fn new() -> Self {
        Self { id: Uuid::new_v4() }
    }
}

impl Default for WebSocketSession {
    fn default() -> Self {
        WebSocketSession::new()
    }
}

impl From<HttpSession> for WebSocketSession {
    fn from(value: HttpSession) -> Self {
        Self { id: value.id }
    }
}
