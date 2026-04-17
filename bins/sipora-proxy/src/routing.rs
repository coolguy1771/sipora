//! SIP proxy forwarding: Max-Forwards, fork ordering, error responses, trace headers.

#![allow(dead_code)]

use sipora_sip::types::header::{ContactValue, Header};
use sipora_sip::types::message::{Request, Response, SipVersion};
use sipora_sip::types::status::StatusCode;

pub struct ProxyRouter {
    max_forwards: u8,
}

impl ProxyRouter {
    pub fn new(max_forwards: u8) -> Self {
        Self { max_forwards }
    }

    /// Check and decrement Max-Forwards. Returns error status if it reaches 0.
    pub fn check_max_forwards(&self, req: &Request) -> Option<StatusCode> {
        tracing::trace!(policy = self.max_forwards, "max-forwards policy");
        match req.max_forwards() {
            Some(0) | Some(1) => Some(StatusCode::TOO_MANY_HOPS),
            None => None,
            Some(_) => None,
        }
    }

    /// Decrement Max-Forwards in the header list
    pub fn decrement_max_forwards(headers: &mut [Header]) {
        for header in headers.iter_mut() {
            if let Header::MaxForwards(mf) = header {
                *mf = mf.saturating_sub(1);
            }
        }
    }

    /// Build fork targets from location service results, sorted by q-value
    pub fn build_fork_targets(contacts: &mut [ContactValue]) -> Vec<&ContactValue> {
        contacts.sort_by(|a, b| {
            b.q_value()
                .partial_cmp(&a.q_value())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        contacts.iter().collect()
    }

    /// Build a 404 Not Found response for a request
    pub fn not_found_response(req: &Request) -> Response {
        build_response(req, StatusCode::NOT_FOUND)
    }

    /// Build a 483 Too Many Hops response
    pub fn too_many_hops_response(req: &Request) -> Response {
        build_response(req, StatusCode::TOO_MANY_HOPS)
    }

    /// Build a 503 Service Unavailable response
    pub fn service_unavailable(req: &Request, retry_after: u32) -> Response {
        let mut resp = build_response(req, StatusCode::SERVICE_UNAVAILABLE);
        resp.headers.push(Header::RetryAfter(retry_after));
        resp
    }

    /// Propagate trace ID header from request to forwarded message
    pub fn propagate_trace_id(req: &Request, trace_header: &str) -> Option<Header> {
        req.headers.iter().find_map(|h| {
            if let Header::Extension { name, value } = h
                && name.eq_ignore_ascii_case(trace_header)
            {
                return Some(Header::Extension {
                    name: name.clone(),
                    value: value.clone(),
                });
            }
            None
        })
    }
}

pub(crate) fn sample_invite(max_forwards: u8) -> Request {
    use sipora_sip::types::header::{CSeq, NameAddr};
    use sipora_sip::types::method::Method;

    Request {
        method: Method::Invite,
        uri: "sip:bob@example.com".into(),
        version: SipVersion::V2_0,
        headers: vec![
            Header::MaxForwards(max_forwards),
            Header::CallId("sipora-warmup@example.com".into()),
            Header::CSeq(CSeq {
                seq: 1,
                method: Method::Invite,
            }),
            Header::From(NameAddr {
                display_name: None,
                uri: "sip:alice@example.com".into(),
                tag: Some("abc".into()),
                params: vec![],
            }),
            Header::To(NameAddr {
                display_name: None,
                uri: "sip:bob@example.com".into(),
                tag: None,
                params: vec![],
            }),
        ],
        body: vec![],
    }
}

pub(crate) fn warmup(config: &sipora_core::config::SiporaConfig, req: &Request) {
    let router = ProxyRouter::new(config.proxy.max_forwards);
    let _ = router.check_max_forwards(req);
    let bad = sample_invite(1);
    let _ = router.check_max_forwards(&bad);
    let mut headers = req.headers.clone();
    ProxyRouter::decrement_max_forwards(&mut headers);
    let mut contacts = vec![ContactValue {
        uri: "sip:fork@example.com".into(),
        q: Some(0.5),
        expires: None,
        params: vec![],
    }];
    let _ = ProxyRouter::build_fork_targets(&mut contacts);
    let _ = ProxyRouter::not_found_response(req);
    let _ = ProxyRouter::too_many_hops_response(req);
    let _ = ProxyRouter::service_unavailable(req, 30);
    let _ = ProxyRouter::propagate_trace_id(req, &config.proxy.trace_header);
    tracing::trace!("proxy routing helpers initialized");
}

fn build_response(req: &Request, status: StatusCode) -> Response {
    let mut headers = Vec::new();

    for h in &req.headers {
        match h {
            Header::Via(_)
            | Header::From(_)
            | Header::To(_)
            | Header::CallId(_)
            | Header::CSeq(_) => headers.push(h.clone()),
            _ => {}
        }
    }
    headers.push(Header::ContentLength(0));

    Response {
        version: SipVersion::V2_0,
        status,
        reason: status.reason_phrase().to_owned(),
        headers,
        body: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sipora_sip::types::header::Header;

    #[test]
    fn test_max_forwards_check() {
        let router = ProxyRouter::new(70);
        let req = sample_invite(1);
        assert_eq!(
            router.check_max_forwards(&req),
            Some(StatusCode::TOO_MANY_HOPS)
        );

        let req = sample_invite(70);
        assert_eq!(router.check_max_forwards(&req), None);
    }

    #[test]
    fn test_decrement_max_forwards() {
        let mut headers = vec![Header::MaxForwards(70)];
        ProxyRouter::decrement_max_forwards(&mut headers);
        assert_eq!(headers[0], Header::MaxForwards(69));
    }
}
