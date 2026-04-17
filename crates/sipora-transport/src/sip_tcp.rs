//! Read one complete SIP message from a byte-oriented stream (TCP / TLS).

use tokio::io::AsyncReadExt;

const HDR_END: &[u8] = b"\r\n\r\n";

pub async fn read_one_message<R: AsyncReadExt + Unpin>(
    r: &mut R,
    max_total: usize,
) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut scratch = [0u8; 4096];
    loop {
        if buf.len() > max_total {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "SIP message exceeds max_total",
            ));
        }
        if let Some(end) = find_header_end(&buf) {
            let cl = content_length_bytes(&buf[..end]).unwrap_or(0);
            let need = end + 4 + cl;
            if buf.len() >= need {
                return Ok(buf[..need].to_vec());
            }
        }
        let n = r.read(&mut scratch).await?;
        if n == 0 {
            return if buf.is_empty() {
                Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "EOF before SIP message",
                ))
            } else {
                Ok(buf)
            };
        }
        buf.extend_from_slice(&scratch[..n]);
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == HDR_END)
}

fn content_length_bytes(headers: &[u8]) -> Option<usize> {
    let s = std::str::from_utf8(headers).ok()?;
    for line in s.split("\r\n") {
        let (name, rest) = line.split_once(':')?;
        if name.trim().eq_ignore_ascii_case("Content-Length") {
            return rest.trim().parse().ok();
        }
    }
    None
}
