use std::env;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[derive(Clone, Debug)]
struct Config {
    listen: String,
    socks_addr: String,
    username: Option<String>,
    password: Option<String>,
    verbose: bool,
}

fn parse_args() -> Config {
    let mut cfg = Config {
        listen: "127.0.0.1:8080".to_string(),
        socks_addr: "127.0.0.1:1080".to_string(),
        username: None,
        password: None,
        verbose: false,
    };

    let mut it = env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--listen" | "-l" => {
                if let Some(v) = it.next() {
                    cfg.listen = v;
                }
            }
            "--socks" | "-s" => {
                if let Some(v) = it.next() {
                    cfg.socks_addr = v;
                }
            }
            "--user" | "-u" => {
                if let Some(v) = it.next() {
                    cfg.username = Some(v);
                }
            }
            "--pass" | "-p" => {
                if let Some(v) = it.next() {
                    cfg.password = Some(v);
                }
            }
            "--verbose" | "-v" => cfg.verbose = true,
            "--help" | "-h" => {
                eprintln!(
                    "http2socks-proxy
Usage: http2socks-proxy [options]
  -l, --listen <addr>   Listen address (default 127.0.0.1:8080)
  -s, --socks <addr>    SOCKS5 server address (default 127.0.0.1:1080)
  -u, --user <user>     SOCKS5 username (optional)
  -p, --pass <pass>     SOCKS5 password (optional)
  -v, --verbose         Verbose logs
  -h, --help            Show help
"
                );
                std::process::exit(0);
            }
            _ => {
                eprintln!("Unknown arg: {arg} (use --help)");
                std::process::exit(2);
            }
        }
    }

    // Если указан только пользователь или только пароль — требуем оба.
    match (&cfg.username, &cfg.password) {
        (Some(_), None) | (None, Some(_)) => {
            eprintln!("Both --user and --pass are required when using auth");
            std::process::exit(2);
        }
        _ => {}
    }

    cfg
}

fn logv(cfg: &Config, msg: &str) {
    if cfg.verbose {
        eprintln!("{msg}");
    }
}

fn main() -> io::Result<()> {
    let cfg = parse_args();
    eprintln!(
        "Listening on {} and proxying via SOCKS5 {}",
        cfg.listen, cfg.socks_addr
    );

    let listener = TcpListener::bind(&cfg.listen)?;
    listener.set_nonblocking(false)?;
    let cfg = Arc::new(cfg);
    for conn in listener.incoming() {
        match conn {
            Ok(mut client) => {
                let cfg = cfg.clone();
                thread::spawn(move || {
                    if let Err(e) = handle_client(&mut client, &cfg)
                        && cfg.verbose
                    {
                        eprintln!("client error: {e}");
                    }
                });
            }
            Err(e) => {
                eprintln!("Accept error: {e}");
            }
        }
    }

    Ok(())
}

fn read_until_double_crlf(stream: &mut TcpStream, buf: &mut Vec<u8>) -> io::Result<usize> {
    let mut tmp = [0u8; 1024];
    loop {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            return Ok(0);
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            return Ok(buf.len());
        }
        // Ограничиваем размер заголовков, чтобы не переполнить буфер.
        if buf.len() > 64 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Headers too large",
            ));
        }
    }
}

use http2socks_proxy::{
    RequestTarget, parse_request_head, socks5_connect, write_modified_request_head,
};

fn pipe_bidirectional(mut a: TcpStream, mut b: TcpStream) -> io::Result<()> {
    let mut ar = a.try_clone()?;
    let mut br = b.try_clone()?;
    let t1 = thread::spawn(move || {
        let _ = io::copy(&mut ar, &mut b);
        let _ = b.shutdown(Shutdown::Write);
    });
    let t2 = thread::spawn(move || {
        let _ = io::copy(&mut br, &mut a);
        let _ = a.shutdown(Shutdown::Write);
    });
    let _ = t1.join();
    let _ = t2.join();
    Ok(())
}

fn handle_client(client: &mut TcpStream, cfg: &Config) -> io::Result<()> {
    client.set_read_timeout(Some(Duration::from_secs(30)))?;
    client.set_write_timeout(Some(Duration::from_secs(30)))?;

    let mut head = Vec::with_capacity(4096);
    if read_until_double_crlf(client, &mut head)? == 0 {
        return Ok(());
    }

    let req = parse_request_head(&head)?;
    match req {
        RequestTarget::Connect { host, port } => {
            logv(cfg, &format!("CONNECT {host}:{port}"));
            let upstream = socks5_connect(
                &cfg.socks_addr,
                &host,
                port,
                cfg.username.as_deref(),
                cfg.password.as_deref(),
            )?;
            // Отвечаем клиенту 200 и начинаем туннелирование трафика.
            client.write_all(
                b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: http2socks-proxy\r\n\r\n",
            )?;
            let a = client.try_clone()?;
            let _ = pipe_bidirectional(a, upstream);
            Ok(())
        }
        RequestTarget::Http {
            method,
            host,
            port,
            path,
            headers,
        } => {
            logv(cfg, &format!("{method} http://{host}:{port}{path}"));
            let mut upstream = socks5_connect(
                &cfg.socks_addr,
                &host,
                port,
                cfg.username.as_deref(),
                cfg.password.as_deref(),
            )?;

            // Гарантируем наличие заголовка Host.
            let has_host = headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("Host"));
            let mut headers_out = headers;
            if !has_host {
                headers_out.push((
                    "Host".to_owned(),
                    if port == 80 {
                        host
                    } else {
                        format!("{host}:{port}")
                    },
                ));
            }

            write_modified_request_head(&mut upstream, &method, &path, &headers_out)?;

            // После заголовков пересылаем оставшиеся данные в обе стороны (тело запроса и ответ).
            // Но сперва отправим наверх байты, уже прочитанные после CRLFCRLF.
            if let Some(pos) = head.windows(4).position(|w| w == b"\r\n\r\n") {
                let after = pos + 4;
                if after < head.len() {
                    upstream.write_all(&head[after..])?;
                }
            }

            let a = client.try_clone()?;
            let _ = pipe_bidirectional(a, upstream);
            Ok(())
        }
    }
}
