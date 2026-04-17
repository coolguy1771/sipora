use crate::types::header::Header;
use crate::types::message::{Request, Response, SipMessage};
use nom::multi::many0;
use nom::{IResult, Parser};

pub fn parse_sip_message(input: &[u8]) -> IResult<&[u8], SipMessage> {
    if input.starts_with(b"SIP/") {
        let (rest, msg) = parse_response(input)?;
        Ok((rest, SipMessage::Response(msg)))
    } else {
        let (rest, msg) = parse_request(input)?;
        Ok((rest, SipMessage::Request(msg)))
    }
}

fn parse_request(input: &[u8]) -> IResult<&[u8], Request> {
    let (rest, (method, uri, version)) = super::request::parse_request_line(input)?;
    let (rest, headers) = many0(super::headers::parse_header_line).parse(rest)?;
    let (rest, _) = nom::bytes::complete::tag(&b"\r\n"[..])(rest)?;
    let body = extract_body(&headers, rest);

    Ok((
        &[],
        Request {
            method,
            uri,
            version,
            headers,
            body,
        },
    ))
}

fn parse_response(input: &[u8]) -> IResult<&[u8], Response> {
    let (rest, (version, status, reason)) = super::response::parse_status_line(input)?;
    let (rest, headers) = many0(super::headers::parse_header_line).parse(rest)?;
    let (rest, _) = nom::bytes::complete::tag(&b"\r\n"[..])(rest)?;
    let body = extract_body(&headers, rest);

    Ok((
        &[],
        Response {
            version,
            status,
            reason,
            headers,
            body,
        },
    ))
}

fn extract_body(headers: &[Header], rest: &[u8]) -> Vec<u8> {
    let content_length = headers.iter().find_map(|h| match h {
        Header::ContentLength(n) => Some(*n as usize),
        _ => None,
    });

    match content_length {
        Some(len) if len > 0 && rest.len() >= len => rest[..len].to_vec(),
        _ if !rest.is_empty() => rest.to_vec(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::method::Method;
    use crate::types::status::StatusCode;

    #[test]
    fn test_parse_invite_request() {
        let msg = b"INVITE sip:bob@example.com SIP/2.0\r\n\
                     Via: SIP/2.0/TLS proxy.example.com:5061;branch=z9hG4bK776\r\n\
                     From: Alice <sip:alice@example.com>;tag=1928301774\r\n\
                     To: Bob <sip:bob@example.com>\r\n\
                     Call-ID: a84b4c76e66710@pc33.example.com\r\n\
                     CSeq: 314159 INVITE\r\n\
                     Max-Forwards: 70\r\n\
                     Content-Length: 0\r\n\
                     \r\n";

        let (_, parsed) = parse_sip_message(msg).unwrap();
        match parsed {
            SipMessage::Request(req) => {
                assert_eq!(req.method, Method::Invite);
                assert_eq!(req.uri, "sip:bob@example.com");
                assert!(req.call_id().is_some());
                assert_eq!(req.max_forwards(), Some(70));
            }
            _ => panic!("expected request"),
        }
    }

    #[test]
    fn test_parse_200_ok_response() {
        let msg = b"SIP/2.0 200 OK\r\n\
                     Via: SIP/2.0/TLS proxy.example.com:5061;branch=z9hG4bK776\r\n\
                     From: Alice <sip:alice@example.com>;tag=1928301774\r\n\
                     To: Bob <sip:bob@example.com>;tag=abc123\r\n\
                     Call-ID: a84b4c76e66710@pc33.example.com\r\n\
                     CSeq: 314159 INVITE\r\n\
                     Content-Length: 0\r\n\
                     \r\n";

        let (_, parsed) = parse_sip_message(msg).unwrap();
        match parsed {
            SipMessage::Response(resp) => {
                assert_eq!(resp.status, StatusCode::OK);
                assert_eq!(resp.reason, "OK");
            }
            _ => panic!("expected response"),
        }
    }

    #[test]
    fn test_parse_register_request() {
        let msg = b"REGISTER sip:example.com SIP/2.0\r\n\
                     Via: SIP/2.0/TLS client.example.com:5061;branch=z9hG4bKnashds7\r\n\
                     From: Alice <sip:alice@example.com>;tag=456248\r\n\
                     To: Alice <sip:alice@example.com>\r\n\
                     Call-ID: 843817637684230@998sdasdh09\r\n\
                     CSeq: 1826 REGISTER\r\n\
                     Contact: <sip:alice@client.example.com:5061;transport=tls>;expires=3600\r\n\
                     Expires: 3600\r\n\
                     Max-Forwards: 70\r\n\
                     Content-Length: 0\r\n\
                     \r\n";

        let (_, parsed) = parse_sip_message(msg).unwrap();
        match parsed {
            SipMessage::Request(req) => {
                assert_eq!(req.method, Method::Register);
                assert_eq!(req.expires(), Some(3600));
            }
            _ => panic!("expected request"),
        }
    }
}
