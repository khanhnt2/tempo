# Tempo - Man in the Middle HTTPS Proxy
The project is inspired by [hudsucker](https://github.com/omjadas/hudsucker) before commit [0594b0c](https://github.com/omjadas/hudsucker/commit/0594b0c1557ab5a807d1ebb8a33d1947a9f34e6e).

At that time, the author didn't upgrade Hyper framework to version 1 so I decided to upgrade by myself.

## What are differrences?
- Better memory management by using [Mimalloc](https://github.com/microsoft/mimalloc)
- Better Websocket duplex channels capturing, works well on Binance
- Support proxy authorization

Check out `logger.rs` in the examples folder.

## Installation
I don't publish the project to crates.io since it's just my side-project in my spare time.
```toml
[dependencies]
tempo = { git = "https://github.com/khanhnt2/tempo", tag = "2025.10.1" }
```
