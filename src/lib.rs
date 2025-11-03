#[macro_use]
extern crate lazy_static;

pub use bytes::Bytes;
pub use http_body_util;
pub use hyper;
pub use hyper_tungstenite::tungstenite;
pub use hyper_util;
use mimalloc::MiMalloc;

mod certificate;
mod proxy;
mod rewind;

pub mod builder;
pub mod handler;
pub mod utils;

pub use builder::Tempo;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;
