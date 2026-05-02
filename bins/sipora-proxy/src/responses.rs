//! Stateless SIP response builders shared by UDP proxy paths.

use sipora_sip::types::header::Header;
use sipora_sip::types::message::{Request, Response, SipMessage, SipVersion};
use sipora_sip::types::method::Method;
use sipora_sip::types::status::StatusCode;

/// Minimum Session-Expires value this proxy accepts (RFC 4028 §7.4).
pub(crate) const PROXY_MIN_SE: u32 = 90;

fn push_standard_headers(out: &mut Vec<Header>, req: &Request) {
    for h in &req.headers {
        match h {
            Header::Via(_)
            | Header::From(_)
            | Header::To(_)
            | Header::CallId(_)
            | Header::CSeq(_) => out.push(h.clone()),
            _ => {}
        }
    }
}

pub(crate) fn sip_options_ok(req: &Request) -> SipMessage {
    let mut headers = Vec::new();
    push_standard_headers(&mut headers, req);
    headers.push(Header::Allow(vec![
        Method::Invite,
        Method::Ack,
        Method::Bye,
        Method::Cancel,
        Method::Register,
        Method::Options,
    ]));
    headers.push(Header::ContentLength(0));
    SipMessage::Response(Response {
        version: SipVersion::V2_0,
        status: StatusCode::OK,
        reason: StatusCode::OK.reason_phrase().to_owned(),
        headers,
        body: Vec::new(),
    })
}

/// Build a 407 with multiple Proxy-Authenticate headers (RFC 8760 dual-algorithm challenge).
pub(crate) fn sip_response_multi_proxy_auth(req: &Request, challenges: &[String]) -> SipMessage {
    let mut headers = Vec::new();
    push_standard_headers(&mut headers, req);
    for ch in challenges {
        headers.push(Header::ProxyAuthenticate(ch.clone()));
    }
    headers.push(Header::ContentLength(0));
    SipMessage::Response(Response {
        version: SipVersion::V2_0,
        status: StatusCode::PROXY_AUTH_REQUIRED,
        reason: StatusCode::PROXY_AUTH_REQUIRED.reason_phrase().to_owned(),
        headers,
        body: Vec::new(),
    })
}

/// Build a 401 with multiple WWW-Authenticate headers (RFC 8760 dual-algorithm challenge).
pub(crate) fn sip_response_multi_www_auth(req: &Request, challenges: &[String]) -> SipMessage {
    let mut headers = Vec::new();
    push_standard_headers(&mut headers, req);
    for ch in challenges {
        headers.push(Header::WwwAuthenticate(ch.clone()));
    }
    headers.push(Header::ContentLength(0));
    SipMessage::Response(Response {
        version: SipVersion::V2_0,
        status: StatusCode::UNAUTHORIZED,
        reason: StatusCode::UNAUTHORIZED.reason_phrase().to_owned(),
        headers,
        body: Vec::new(),
    })
}

/// Build a 422 Session Interval Too Small response with a Min-SE header.
pub(crate) fn sip_response_with_min_se(req: &Request, min_se: u32) -> SipMessage {
    let mut headers = Vec::new();
    push_standard_headers(&mut headers, req);
    headers.push(Header::MinSE(min_se));
    headers.push(Header::ContentLength(0));
    SipMessage::Response(Response {
        version: SipVersion::V2_0,
        status: StatusCode::SESSION_INTERVAL_TOO_SMALL,
        reason: StatusCode::SESSION_INTERVAL_TOO_SMALL
            .reason_phrase()
            .to_owned(),
        headers,
        body: Vec::new(),
    })
}

pub(crate) fn sip_response(req: &Request, status: StatusCode) -> SipMessage {
    let mut headers = Vec::new();
    push_standard_headers(&mut headers, req);
    headers.push(Header::ContentLength(0));
    SipMessage::Response(Response {
        version: SipVersion::V2_0,
        status,
        reason: status.reason_phrase().to_owned(),
        headers,
        body: Vec::new(),
    })
}

pub(crate) fn sip_response_expires(req: &Request, status: StatusCode, expires: u32) -> SipMessage {
    let mut headers = Vec::new();
    push_standard_headers(&mut headers, req);
    headers.push(Header::Expires(expires));
    headers.push(Header::ContentLength(0));
    SipMessage::Response(Response {
        version: SipVersion::V2_0,
        status,
        reason: status.reason_phrase().to_owned(),
        headers,
        body: Vec::new(),
    })
}

pub(crate) fn sip_ok_sip_etag(req: &Request, etag: String) -> SipMessage {
    let mut headers = Vec::new();
    push_standard_headers(&mut headers, req);
    headers.push(Header::SipEtag(etag));
    headers.push(Header::ContentLength(0));
    SipMessage::Response(Response {
        version: SipVersion::V2_0,
        status: StatusCode::OK,
        reason: StatusCode::OK.reason_phrase().to_owned(),
        headers,
        body: Vec::new(),
    })
}

pub(crate) fn simple_ok(req: &Request) -> SipMessage {
    let mut headers = Vec::new();
    push_standard_headers(&mut headers, req);
    for h in &req.headers {
        if let Header::Contact(_) = h {
            headers.push(h.clone());
        }
    }
    headers.push(Header::ContentLength(0));
    SipMessage::Response(Response {
        version: SipVersion::V2_0,
        status: StatusCode::OK,
        reason: StatusCode::OK.reason_phrase().to_owned(),
        headers,
        body: Vec::new(),
    })
}
