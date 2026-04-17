//! Max-Forwards handling and 483 responses (aligned with `sipora-proxy`).

use sipora_sip::types::header::Header;
use sipora_sip::types::message::{Request, Response, SipVersion};
use sipora_sip::types::status::StatusCode;

#[derive(Clone)]
pub struct ProxyRouter {
    max_forwards: u8,
}

impl ProxyRouter {
    pub fn new(max_forwards: u8) -> Self {
        Self { max_forwards }
    }

    pub fn check_max_forwards(&self, req: &Request) -> Option<StatusCode> {
        let _ = self.max_forwards;
        match req.max_forwards() {
            Some(0) | Some(1) => Some(StatusCode::TOO_MANY_HOPS),
            _ => None,
        }
    }

    pub fn decrement_max_forwards(headers: &mut [Header]) {
        for header in headers.iter_mut() {
            if let Header::MaxForwards(mf) = header {
                *mf = mf.saturating_sub(1);
            }
        }
    }

    pub fn too_many_hops_response(req: &Request) -> Response {
        build_response(req, StatusCode::TOO_MANY_HOPS)
    }
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
