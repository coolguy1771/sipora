use crate::types::header::*;
use crate::types::method::Method;
use nom::IResult;
use nom::bytes::complete::{tag, tag_no_case, take_while, take_while1};
use nom::character::complete::space0;

fn header_value(input: &[u8]) -> IResult<&[u8], &[u8]> {
    take_while(|c| c != b'\r' && c != b'\n')(input)
}

fn to_str(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn trim_str(b: &[u8]) -> String {
    String::from_utf8_lossy(b).trim().to_owned()
}

pub fn parse_header_line(input: &[u8]) -> IResult<&[u8], Header> {
    let (rest, name) = take_while1(|c: u8| c != b':' && c != b'\r')(input)?;
    let (rest, _) = tag(&b":"[..])(rest)?;
    let (rest, _) = space0(rest)?;
    let (rest, value) = header_value(rest)?;
    let (rest, _) = super::crlf(rest)?;

    let name_str = trim_str(name);
    let header = match_header(&name_str, value);
    Ok((rest, header))
}

fn match_header(name: &str, value: &[u8]) -> Header {
    match name.to_ascii_lowercase().as_str() {
        "via" | "v" => parse_via_value(value)
            .map(|(_, v)| Header::Via(v))
            .unwrap_or_else(|_| ext(name, value)),
        "from" | "f" => parse_name_addr(value)
            .map(|(_, na)| Header::From(na))
            .unwrap_or_else(|_| ext(name, value)),
        "to" | "t" => parse_name_addr(value)
            .map(|(_, na)| Header::To(na))
            .unwrap_or_else(|_| ext(name, value)),
        "call-id" | "i" => Header::CallId(trim_str(value)),
        "cseq" => parse_cseq_value(value)
            .map(|(_, cs)| Header::CSeq(cs))
            .unwrap_or_else(|_| ext(name, value)),
        "contact" | "m" => parse_contact_value(value)
            .map(|(_, cs)| Header::Contact(cs))
            .unwrap_or_else(|_| ext(name, value)),
        "max-forwards" => parse_u32_val(value)
            .map(|n| Header::MaxForwards(n as u8))
            .unwrap_or_else(|| ext(name, value)),
        "content-length" | "l" => parse_u32_val(value)
            .map(Header::ContentLength)
            .unwrap_or_else(|| ext(name, value)),
        "content-type" | "c" => Header::ContentType(trim_str(value)),
        "expires" => parse_u32_val(value)
            .map(Header::Expires)
            .unwrap_or_else(|| ext(name, value)),
        "min-expires" => parse_u32_val(value)
            .map(Header::MinExpires)
            .unwrap_or_else(|| ext(name, value)),
        "route" => Header::Route(split_comma_list(value)),
        "record-route" => Header::RecordRoute(split_comma_list(value)),
        "allow" => Header::Allow(split_methods(value)),
        "supported" | "k" => Header::Supported(split_comma_list(value)),
        "require" => Header::Require(split_comma_list(value)),
        "authorization" => Header::Authorization(trim_str(value)),
        "www-authenticate" => Header::WwwAuthenticate(trim_str(value)),
        "proxy-authenticate" => Header::ProxyAuthenticate(trim_str(value)),
        "proxy-authorization" => Header::ProxyAuthorization(trim_str(value)),
        "user-agent" => Header::UserAgent(trim_str(value)),
        "retry-after" => parse_u32_val(value)
            .map(Header::RetryAfter)
            .unwrap_or_else(|| ext(name, value)),
        "rseq" => parse_u32_val(value)
            .map(Header::RSeq)
            .unwrap_or_else(|| ext(name, value)),
        "rack" => parse_rack_value(value).unwrap_or_else(|| ext(name, value)),
        "session-expires" | "x" => parse_session_expires(value).unwrap_or_else(|| ext(name, value)),
        "min-se" => parse_u32_val(value)
            .map(Header::MinSE)
            .unwrap_or_else(|| ext(name, value)),
        _ => ext(name, value),
    }
}

fn parse_rack_value(input: &[u8]) -> Option<Header> {
    let s = trim_str(input);
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() < 3 {
        return None;
    }
    let rseq = parts[0].parse().ok()?;
    let cseq = parts[1].parse().ok()?;
    let method = Method::from_bytes(parts[2].as_bytes());
    Some(Header::RAck { rseq, cseq, method })
}

fn parse_session_expires(input: &[u8]) -> Option<Header> {
    let s = trim_str(input);
    let (num_str, rest) = match s.split_once(';') {
        Some((n, r)) => (n, Some(r)),
        None => (s.as_str(), None),
    };
    let delta_seconds = num_str.trim().parse().ok()?;
    let refresher = rest.and_then(|params| {
        params.split(';').find_map(|p| {
            p.trim()
                .strip_prefix("refresher=")
                .and_then(|r| match r.trim() {
                    "uac" => Some(Refresher::Uac),
                    "uas" => Some(Refresher::Uas),
                    _ => None,
                })
        })
    });
    Some(Header::SessionExpires {
        delta_seconds,
        refresher,
    })
}

fn ext(name: &str, value: &[u8]) -> Header {
    Header::Extension {
        name: name.to_owned(),
        value: trim_str(value),
    }
}

fn parse_u32_val(input: &[u8]) -> Option<u32> {
    let trimmed = String::from_utf8_lossy(input).trim().to_owned();
    trimmed.parse().ok()
}

fn split_comma_list(input: &[u8]) -> Vec<String> {
    let s = String::from_utf8_lossy(input);
    s.split(',').map(|u| u.trim().to_owned()).collect()
}

fn split_methods(input: &[u8]) -> Vec<Method> {
    let s = String::from_utf8_lossy(input);
    s.split(',')
        .map(|m| Method::from_bytes(m.trim().as_bytes()))
        .collect()
}

fn parse_via_value(input: &[u8]) -> IResult<&[u8], Via> {
    let (rest, _) = tag_no_case(&b"SIP/"[..])(input)?;
    let (rest, _) = take_while1(|c: u8| c.is_ascii_digit() || c == b'.')(rest)?;
    let (rest, _) = tag(&b"/"[..])(rest)?;
    let (rest, transport_bytes) = take_while1(|c: u8| c.is_ascii_alphanumeric())(rest)?;
    let (rest, _) = space0(rest)?;

    let transport = match transport_bytes.to_ascii_uppercase().as_slice() {
        b"UDP" => Transport::Udp,
        b"TCP" => Transport::Tcp,
        b"TLS" => Transport::Tls,
        b"WS" => Transport::Ws,
        b"WSS" => Transport::Wss,
        other => Transport::Other(to_str(other)),
    };

    let (rest, host_port) = take_while(|c: u8| c != b';' && c != b'\r' && c != b',')(rest)?;
    let hp = trim_str(host_port);
    let (host, port) = parse_host_port(&hp);

    let params_str = to_str(rest);
    let (branch, received, rport, extra_params) = parse_via_params(&params_str);

    Ok((
        b"" as &[u8],
        Via {
            transport,
            host,
            port,
            branch,
            received,
            rport,
            params: extra_params,
        },
    ))
}

fn parse_host_port(s: &str) -> (String, Option<u16>) {
    if let Some(idx) = s.rfind(':') {
        let port_str = &s[idx + 1..];
        if let Ok(port) = port_str.parse::<u16>() {
            return (s[..idx].to_owned(), Some(port));
        }
    }
    (s.to_owned(), None)
}

type ViaParams = (
    String,
    Option<String>,
    RportParam,
    Vec<(String, Option<String>)>,
);

fn parse_via_params(s: &str) -> ViaParams {
    let mut branch = String::new();
    let mut received = None;
    let mut rport = RportParam::Absent;
    let mut extras = Vec::new();

    for part in s.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((k, v)) = part.split_once('=') {
            let k = k.trim().to_ascii_lowercase();
            let v = v.trim().to_owned();
            match k.as_str() {
                "branch" => branch = v,
                "received" => received = Some(v),
                "rport" => {
                    if let Ok(port) = v.parse() {
                        rport = RportParam::Filled(port);
                    } else {
                        extras.push((k, Some(v)));
                    }
                }
                _ => extras.push((k, Some(v))),
            }
        } else {
            let k = part.to_ascii_lowercase();
            if k == "rport" {
                rport = RportParam::Requested;
            } else {
                extras.push((k, None));
            }
        }
    }

    (branch, received, rport, extras)
}

fn parse_name_addr(input: &[u8]) -> IResult<&[u8], NameAddr> {
    let s = trim_str(input);
    let (display_name, uri, rest_params) = split_name_addr(&s);

    let mut tag_val = None;
    let mut params = Vec::new();
    for part in rest_params.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((k, v)) = part.split_once('=') {
            let k = k.trim().to_ascii_lowercase();
            let v = v.trim().to_owned();
            if k == "tag" {
                tag_val = Some(v);
            } else {
                params.push((k, Some(v)));
            }
        } else {
            params.push((part.to_ascii_lowercase(), None));
        }
    }

    Ok((
        b"",
        NameAddr {
            display_name,
            uri,
            tag: tag_val,
            params,
        },
    ))
}

fn split_name_addr(s: &str) -> (Option<String>, String, String) {
    if let Some(start) = s.find('<') {
        let display = s[..start].trim().trim_matches('"');
        let dn = if display.is_empty() {
            None
        } else {
            Some(display.to_owned())
        };
        if let Some(end) = s.find('>') {
            let uri = s[start + 1..end].to_owned();
            let rest = if end + 1 < s.len() {
                s[end + 1..].to_owned()
            } else {
                String::new()
            };
            return (dn, uri, rest);
        }
    }
    let parts: Vec<&str> = s.splitn(2, ';').collect();
    let uri = parts[0].trim().to_owned();
    let rest = parts.get(1).unwrap_or(&"").to_string();
    (None, uri, rest)
}

fn parse_cseq_value(input: &[u8]) -> IResult<&[u8], CSeq> {
    let s = trim_str(input);
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Space,
        )));
    }
    let seq = parts[0].parse::<u32>().unwrap_or(0);
    let method = Method::from_bytes(parts[1].as_bytes());
    Ok((b"", CSeq { seq, method }))
}

fn parse_contact_value(input: &[u8]) -> IResult<&[u8], Vec<ContactValue>> {
    let s = trim_str(input);
    if s == "*" {
        return Ok((
            b"",
            vec![ContactValue {
                uri: "*".to_owned(),
                q: None,
                expires: None,
                params: vec![],
            }],
        ));
    }

    let contacts: Vec<ContactValue> = s
        .split(',')
        .map(|part| {
            let part = part.trim();
            let (_, uri_str, params_str) = split_name_addr(part);
            let mut q = None;
            let mut expires = None;
            let mut params = Vec::new();

            for p in params_str.split(';') {
                let p = p.trim();
                if p.is_empty() {
                    continue;
                }
                if let Some((k, v)) = p.split_once('=') {
                    let k = k.trim().to_ascii_lowercase();
                    let v = v.trim().to_owned();
                    match k.as_str() {
                        "q" => q = v.parse().ok(),
                        "expires" => expires = v.parse().ok(),
                        _ => params.push((k, Some(v))),
                    }
                } else {
                    params.push((p.to_ascii_lowercase(), None));
                }
            }

            ContactValue {
                uri: uri_str,
                q,
                expires,
                params,
            }
        })
        .collect();

    Ok((b"", contacts))
}
