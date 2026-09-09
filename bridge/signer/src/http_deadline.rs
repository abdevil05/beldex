//! Finite application deadlines for blocking RPC calls, including response bodies.
use std::time::Duration;
pub const RPC_TIMEOUT: Duration = Duration::from_secs(15);
pub fn post(url: &str) -> ureq::Request {
    post_with_timeout(url, RPC_TIMEOUT)
}
fn post_with_timeout(url: &str, limit: Duration) -> ureq::Request {
    ureq::AgentBuilder::new()
        .timeout_connect(limit.min(Duration::from_secs(5)))
        .timeout_read(limit.min(Duration::from_secs(10)))
        .timeout_write(limit.min(Duration::from_secs(10)))
        .timeout(limit)
        .build()
        .post(url)
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::time::Instant;
    fn stalled_response(headers: bool) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut buf = [0u8; 4096];
            stream.read(&mut buf).unwrap();
            if headers {
                stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n").unwrap();
            }
            std::thread::sleep(Duration::from_millis(500));
        });
        let start = Instant::now();
        let result = post_with_timeout(&url, Duration::from_millis(100))
            .send_json(serde_json::json!({"jsonrpc":"2.0","method":"test","id":1}));
        if headers {
            assert!(result.unwrap().into_json::<serde_json::Value>().is_err());
        } else {
            assert!(result.is_err());
        }
        assert!(
            start.elapsed() < Duration::from_millis(450),
            "RPC waited for peer close instead of its deadline"
        );
        server.join().unwrap();
    }
    #[test]
    fn stalled_response_headers_hit_deadline() {
        stalled_response(false);
    }
    #[test]
    fn stalled_response_body_hits_deadline() {
        stalled_response(true);
    }
}
