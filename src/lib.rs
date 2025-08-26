#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::module_name_repetitions)]

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestTarget {
    Connect {
        host: String,
        port: u16,
    },
    Http {
        method: String,
        host: String,
        port: u16,
        path: String,
        headers: Vec<(String, String)>,
    },
}

pub fn parse_request_head(head: &[u8]) -> io::Result<RequestTarget> {
    let s = std::str::from_utf8(head)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid utf8 in request"))?;
    let mut lines = s.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "empty request"))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad request line"))?
        .to_owned();
    let target = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad request line"))?;
    let _ = parts.next();

    let mut headers: Vec<(String, String)> = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }

    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port_str) = target.split_once(':').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "CONNECT target must be host:port",
            )
        })?;
        let port = port_str
            .parse::<u16>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid port"))?;
        return Ok(RequestTarget::Connect {
            host: host.to_owned(),
            port,
        });
    }

    let uri = target;
    let rest = uri
        .strip_prefix("http://")
        .or_else(|| uri.strip_prefix("https://"))
        .unwrap_or(uri);
    let (authority, pathq) = rest
        .find('/')
        .map_or((rest, "/"), |idx| (&rest[..idx], &rest[idx..]));
    let (host, port) = if let Some((h, p)) = authority.rsplit_once(':') {
        p.parse::<u16>()
            .map_or_else(|_| (authority.to_owned(), 80), |pn| (h.to_owned(), pn))
    } else {
        (authority.to_owned(), 80)
    };
    Ok(RequestTarget::Http {
        method,
        host,
        port,
        path: pathq.to_owned(),
        headers,
    })
}

pub fn write_modified_request_head<W: Write>(
    w: &mut W,
    method: &str,
    path: &str,
    headers: &[(String, String)],
) -> io::Result<()> {
    write!(w, "{method} {path} HTTP/1.1\r\n")?;
    let mut has_connection = false;
    for (k, v) in headers {
        let k_lower = k.to_ascii_lowercase();
        if k_lower == "proxy-connection" || k_lower == "proxy-authorization" {
            continue;
        }
        if k_lower == "connection" {
            has_connection = true;
        }
        writeln!(w, "{k}: {v}")?;
    }
    if !has_connection {
        writeln!(w, "Connection: close")?;
    }
    write!(w, "\r\n")?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
pub fn socks5_connect(
    socks_addr: &str,
    host: &str,
    port: u16,
    user: Option<&str>,
    pass: Option<&str>,
) -> io::Result<TcpStream> {
    let mut s = TcpStream::connect(socks_addr)?;
    s.set_read_timeout(Some(Duration::from_secs(30)))?;
    s.set_write_timeout(Some(Duration::from_secs(30)))?;

    // Приветствие клиента SOCKS5 (greeting).
    let mut methods: Vec<u8> = vec![0x00]; // без аутентификации
    let use_auth = user.is_some() && pass.is_some();
    if use_auth {
        methods.push(0x02);
    }
    let mut buf = Vec::with_capacity(4);
    buf.push(0x05); // версия
    buf.push(
        u8::try_from(methods.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "too many auth methods"))?,
    );
    buf.extend_from_slice(&methods);
    s.write_all(&buf)?;

    let mut resp = [0u8; 2];
    s.read_exact(&mut resp)?;
    if resp[0] != 0x05 {
        return Err(io::Error::other("SOCKS5 bad version"));
    }
    match resp[1] {
        0x00 => { /* без аутентификации */ }
        0x02 => {
            if !use_auth {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "SOCKS5 server requires auth",
                ));
            }
            let (u, p) = match (user, pass) {
                (Some(u), Some(p)) => (u.as_bytes(), p.as_bytes()),
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "SOCKS5 auth missing creds",
                    ));
                }
            };
            if u.len() > 255 || p.len() > 255 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "username/password too long",
                ));
            }
            let mut a = Vec::with_capacity(3 + u.len() + p.len());
            a.push(0x01); // версия подпроцедуры аутентификации
            let ulen = u8::try_from(u.len())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "username too long"))?;
            a.push(ulen);
            a.extend_from_slice(u);
            let plen = u8::try_from(p.len())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "password too long"))?;
            a.push(plen);
            a.extend_from_slice(p);
            s.write_all(&a)?;
            let mut ar = [0u8; 2];
            s.read_exact(&mut ar)?;
            if ar[1] != 0x00 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "SOCKS5 auth failed",
                ));
            }
        }
        0xFF => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SOCKS5 no acceptable auth",
            ));
        }
        _ => return Err(io::Error::other("SOCKS5 unsupported method")),
    }

    // Запрос CONNECT к целевому хосту через SOCKS5
    let mut req = Vec::with_capacity(512);
    req.push(0x05); // версия
    req.push(0x01); // команда CONNECT
    req.push(0x00); // зарезервировано

    // Адрес назначения
    if let Ok(addr) = host.parse::<std::net::Ipv4Addr>() {
        req.push(0x01); // IPv4-адрес
        req.extend_from_slice(&addr.octets());
    } else if let Ok(addr6) = host.parse::<std::net::Ipv6Addr>() {
        req.push(0x04); // IPv6-адрес
        req.extend_from_slice(&addr6.octets());
    } else {
        let hb = host.as_bytes();
        if hb.len() > 255 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "hostname too long",
            ));
        }
        req.push(0x03); // доменное имя
        let hlen = u8::try_from(hb.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "hostname too long"))?;
        req.push(hlen);
        req.extend_from_slice(hb);
    }
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req)?;

    // Ответ: VER REP RSV ATYP BND.ADDR BND.PORT
    let mut hdr = [0u8; 4];
    s.read_exact(&mut hdr)?;
    if hdr[0] != 0x05 {
        return Err(io::Error::other("SOCKS5 bad version in reply"));
    }
    if hdr[1] != 0x00 {
        let reply_code = hdr[1];
        return Err(io::Error::other(format!(
            "SOCKS5 connect failed: 0x{reply_code:02x}"
        )));
    }
    // Считываем поле адреса согласно типу ATYP
    match hdr[3] {
        0x01 => {
            let mut skip = [0u8; 4];
            s.read_exact(&mut skip)?;
        }
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l)?;
            let mut n = vec![0u8; l[0] as usize];
            s.read_exact(&mut n)?;
        }
        0x04 => {
            let mut skip = [0u8; 16];
            s.read_exact(&mut skip)?;
        }
        _ => return Err(io::Error::other("SOCKS5 bad ATYP in reply")),
    }
    let mut p = [0u8; 2];
    s.read_exact(&mut p)?;

    Ok(s)
}
