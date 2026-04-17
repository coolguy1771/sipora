//! Static redirect rules for SIP 3xx responses.

#![allow(dead_code)]

use sipora_sip::types::header::{ContactValue, Header};
use sipora_sip::types::message::{Request, Response, SipVersion};
use sipora_sip::types::status::StatusCode;

#[derive(Debug, Clone)]
pub struct RedirectRule {
    pub id: String,
    pub from_uri: String,
    pub to_uri: String,
    pub rule_type: RedirectType,
    pub q_value: f32,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RedirectType {
    Permanent,
    Temporary,
}

pub struct RedirectServer {
    default_expires: u32,
}

impl RedirectServer {
    pub fn new(default_expires: u32) -> Self {
        Self { default_expires }
    }

    /// Build a 302/301 redirect response from matched rules
    pub fn build_redirect_response(
        &self,
        req: &Request,
        rules: &[RedirectRule],
    ) -> Option<Response> {
        if rules.is_empty() {
            return None;
        }

        let is_permanent = rules.iter().any(|r| r.rule_type == RedirectType::Permanent);
        let status = if is_permanent {
            StatusCode::MOVED_PERMANENTLY
        } else {
            StatusCode::MOVED_TEMPORARILY
        };

        let contacts: Vec<ContactValue> = rules
            .iter()
            .map(|rule| ContactValue {
                uri: rule.to_uri.clone(),
                q: Some(rule.q_value),
                expires: Some(self.default_expires),
                params: vec![],
            })
            .collect();

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
        headers.push(Header::Contact(contacts));
        headers.push(Header::ContentLength(0));

        Some(Response {
            version: SipVersion::V2_0,
            status,
            reason: status.reason_phrase().to_owned(),
            headers,
            body: Vec::new(),
        })
    }
}

pub(crate) fn warmup(req: &Request, default_expires: u32) {
    let server = RedirectServer::new(default_expires);
    let rules = vec![RedirectRule {
        id: "warmup".into(),
        from_uri: "sip:alice@example.com".into(),
        to_uri: "sip:bob@example.com".into(),
        rule_type: RedirectType::Temporary,
        q_value: 1.0,
    }];
    if let Some(resp) = server.build_redirect_response(req, &rules) {
        let rule = &rules[0];
        tracing::debug!(
            status = resp.status.0,
            rule_id = %rule.id,
            from = %rule.from_uri,
            "redirect warmup ok"
        );
    }
}
