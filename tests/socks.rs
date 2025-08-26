use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use http2socks_proxy::socks5_connect;

fn spawn_mock_socks(expect_auth: bool, expect_host: &str, expect_port: u16) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap();
    let host = expect_host.to_string();
    thread::spawn(move || {
        let (mut s, _) = listener.accept().expect("accept");
        // Читаем приветствие клиента (greeting).
        let mut g = [0u8; 3];
        s.read_exact(&mut g[..2]).unwrap();
        assert_eq!(g[0], 0x05);
        let n = g[1] as usize;
        let mut methods = vec![0u8; n];
        s.read_exact(&mut methods).unwrap();
        if expect_auth {
            // Сервер выбирает метод аутентификации: username/password.
            s.write_all(&[0x05, 0x02]).unwrap();
            // Затем читаем сабпротокол аутентификации (RFC1929).
            let mut ver = [0u8; 1];
            s.read_exact(&mut ver).unwrap();
            assert_eq!(ver[0], 0x01);
            let mut ulen = [0u8; 1];
            s.read_exact(&mut ulen).unwrap();
            let mut ubuf = vec![0u8; ulen[0] as usize];
            s.read_exact(&mut ubuf).unwrap();
            let mut plen = [0u8; 1];
            s.read_exact(&mut plen).unwrap();
            let mut pbuf = vec![0u8; plen[0] as usize];
            s.read_exact(&mut pbuf).unwrap();
            // Принять аутентификацию (успех).
            s.write_all(&[0x01, 0x00]).unwrap();
        } else {
            // Выбор метода без аутентификации.
            s.write_all(&[0x05, 0x00]).unwrap();
        }

        // Читаем запрос CONNECT от клиента.
        let mut hdr = [0u8; 4];
        s.read_exact(&mut hdr).unwrap();
        assert_eq!(
            hdr,
            [
                0x05,
                0x01,
                0x00,
                if host.parse::<std::net::Ipv4Addr>().is_ok() {
                    0x01
                } else if host.parse::<std::net::Ipv6Addr>().is_ok() {
                    0x04
                } else {
                    0x03
                }
            ]
        );

        match hdr[3] {
            0x01 => {
                let mut addr = [0u8; 4];
                s.read_exact(&mut addr).unwrap();
            }
            0x04 => {
                let mut addr = [0u8; 16];
                s.read_exact(&mut addr).unwrap();
            }
            0x03 => {
                let mut l = [0u8; 1];
                s.read_exact(&mut l).unwrap();
                let mut name = vec![0u8; l[0] as usize];
                s.read_exact(&mut name).unwrap();
                assert_eq!(String::from_utf8(name).unwrap(), host);
            }
            _ => unreachable!(),
        }
        let mut portb = [0u8; 2];
        s.read_exact(&mut portb).unwrap();
        let port = u16::from_be_bytes(portb);
        assert_eq!(port, expect_port);

        // Отвечаем успехом, якобы привязаны к 0.0.0.0:0.
        s.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .unwrap();

        // Ненадолго держим соединение открытым.
        let _ = s.flush();
    });
    addr.to_string()
}

#[test]
fn socks_no_auth_domain() {
    let addr = spawn_mock_socks(false, "example.com", 80);
    let stream = socks5_connect(&addr, "example.com", 80, None, None).expect("connect via socks");
    let _ = stream.shutdown(std::net::Shutdown::Both);
}

#[test]
fn socks_with_auth_ipv4() {
    let addr = spawn_mock_socks(true, "127.0.0.1", 8080);
    let stream =
        socks5_connect(&addr, "127.0.0.1", 8080, Some("u"), Some("p")).expect("connect via socks");
    let _ = stream.shutdown(std::net::Shutdown::Both);
}
