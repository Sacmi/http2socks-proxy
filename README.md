http2socks-proxy
=================

Lightweight HTTP(S) to SOCKS5 proxy written in Rust using only the standard library.

Features
- HTTP CONNECT tunneling for HTTPS and arbitrary TCP.
- Absolute-form HTTP requests (GET/POST via proxy) with request-line rewrite.
- Minimal, dependency-free SOCKS5 client with optional username/password auth.
- Simple CLI flags and optional verbose logging.

Usage
- Build: `cargo build --release`
- Run: `./target/release/http2socks-proxy [options]`

Options
- `-l, --listen <addr>`: Listen address (default `127.0.0.1:8080`).
- `-s, --socks <addr>`: Upstream SOCKS5 server address (default `127.0.0.1:1080`).
- `-u, --user <user>`: SOCKS5 username (optional; requires `--pass`).
- `-p, --pass <pass>`: SOCKS5 password (optional; requires `--user`).
- `-v, --verbose`: Verbose logs.

Notes
- For non-CONNECT HTTP requests, the proxy rewrites the request line to origin-form and forwards headers, dropping `Proxy-Connection` and `Proxy-Authorization`. It forces `Connection: close` if absent to simplify lifecycle.
- The proxy currently handles one request per client connection. Most clients obey `Connection: close` and reconnect as needed.
- Timeouts are set to 30s for reads/writes on both client and SOCKS connections.

Example
- Forward local HTTP proxy to a local SOCKS5 server on 1080:
  `http2socks-proxy -l 127.0.0.1:3128 -s 127.0.0.1:1080 -v`

