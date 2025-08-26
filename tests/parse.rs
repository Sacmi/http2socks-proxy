use http2socks_proxy::{RequestTarget, parse_request_head};

#[test]
fn parse_connect() {
    let req = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
    let parsed = parse_request_head(req).expect("parse CONNECT");
    match parsed {
        RequestTarget::Connect { host, port } => {
            assert_eq!(host, "example.com");
            assert_eq!(port, 443);
        }
        _ => panic!("expected CONNECT"),
    }
}

#[test]
fn parse_absolute_form() {
    let req = b"GET http://example.com:8080/path?q=1 HTTP/1.1\r\nUser-Agent: x\r\n\r\n";
    let parsed = parse_request_head(req).expect("parse GET");
    match parsed {
        RequestTarget::Http {
            method,
            host,
            port,
            path,
            ..
        } => {
            assert_eq!(method, "GET");
            assert_eq!(host, "example.com");
            assert_eq!(port, 8080);
            assert_eq!(path, "/path?q=1");
        }
        _ => panic!("expected HTTP"),
    }
}
