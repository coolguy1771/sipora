use crate::codec::B2buaDialog;
use sipora_sip::types::header::{CSeq, Header, NameAddr};
use sipora_sip::types::message::{Request, Response};
use sipora_sip::types::method::Method;
use std::collections::HashMap;
use std::net::SocketAddr;

#[derive(Debug)]
pub struct B2buaLeg {
    pub call_id: Option<String>,
    pub local_tag: Option<String>,
    pub remote_tag: Option<String>,
    pub route_set: Vec<String>,
    pub last_local_cseq: Option<u32>,
    pub last_remote_cseq: Option<u32>,
    pub peer_addr: SocketAddr,
}

pub struct B2buaCall {
    pub uac_leg: B2buaLeg,
    pub uas_leg: B2buaLeg,
    pub dialog: B2buaDialog,
}

#[derive(Default)]
pub struct B2buaCallStore {
    calls: HashMap<String, B2buaCall>,
    pending: HashMap<PendingResponseKey, SocketAddr>,
}

impl B2buaCallStore {
    pub fn record_invite(
        &mut self,
        client_req: &Request,
        downstream_req: &Request,
        client_addr: SocketAddr,
        downstream_addr: SocketAddr,
    ) -> Option<()> {
        let call = B2buaCall::from_initial_invite_pair(
            client_req,
            downstream_req,
            client_addr,
            downstream_addr,
        )?;
        let call_id = call.uas_leg.call_id.clone()?;
        self.calls.insert(call_id, call);
        Some(())
    }

    pub fn record_pending_request(&mut self, req: &Request, client_addr: SocketAddr) -> Option<()> {
        let key = PendingResponseKey::from_request(req)?;
        self.pending.insert(key, client_addr);
        Some(())
    }

    pub fn client_addr_for_response(&mut self, resp: &Response) -> Option<SocketAddr> {
        let call_id = resp.call_id()?;
        if let Some(call) = self.calls.get_mut(call_id)
            && let Some(client_addr) = call.client_addr_for_response(resp)
        {
            return Some(client_addr);
        }
        let key = PendingResponseKey::from_response(resp)?;
        self.pending.get(&key).copied()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PendingResponseKey {
    call_id: String,
    cseq: u32,
    method: Method,
}

impl PendingResponseKey {
    fn from_request(req: &Request) -> Option<Self> {
        let cseq = req.cseq()?;
        Some(Self {
            call_id: req.call_id()?.to_owned(),
            cseq: cseq.seq,
            method: cseq.method.clone(),
        })
    }

    fn from_response(resp: &Response) -> Option<Self> {
        let cseq = resp.cseq()?;
        Some(Self {
            call_id: resp.call_id()?.to_owned(),
            cseq: cseq.seq,
            method: cseq.method.clone(),
        })
    }
}

impl B2buaCall {
    pub fn from_initial_invite_pair(
        req: &Request,
        downstream_req: &Request,
        client_addr: SocketAddr,
        downstream_addr: SocketAddr,
    ) -> Option<Self> {
        if req.method != Method::Invite {
            return None;
        }
        let call_id = req.call_id()?.to_owned();
        let cseq = req.cseq().map(|c| c.seq);
        let mut call = Self {
            uac_leg: B2buaLeg::from_request(req, client_addr),
            uas_leg: B2buaLeg::new(call_id, downstream_addr),
            dialog: B2buaDialog::new(),
        };
        call.uas_leg.local_tag = req.from_header().and_then(tag_from_name_addr);
        call.uas_leg.last_local_cseq = cseq;
        call.record_initial_offer(req, downstream_req);
        Some(call)
    }

    pub fn client_addr_for_response(&mut self, resp: &Response) -> Option<SocketAddr> {
        let call_id = resp.call_id()?;
        if self.uas_leg.call_id.as_deref() != Some(call_id) {
            return None;
        }
        if !self.matches_uas_response(resp) {
            return None;
        }
        self.uas_leg.update_from_response(resp);
        self.record_downstream_answer(resp);
        Some(self.uac_leg.peer_addr)
    }

    fn matches_uas_response(&self, resp: &Response) -> bool {
        self.matches_invite_cseq(resp) && self.matches_uas_tags(resp)
    }

    fn matches_invite_cseq(&self, resp: &Response) -> bool {
        let Some(cseq) = resp.cseq() else {
            return false;
        };
        cseq.method == Method::Invite && self.uas_leg.last_local_cseq == Some(cseq.seq)
    }

    fn matches_uas_tags(&self, resp: &Response) -> bool {
        let from_tag = first_name_addr_tag(&resp.headers, HeaderSide::From);
        let to_tag = first_name_addr_tag(&resp.headers, HeaderSide::To);
        tags_match(self.uas_leg.local_tag.as_deref(), from_tag.as_deref())
            && tags_match(self.uas_leg.remote_tag.as_deref(), to_tag.as_deref())
    }

    fn record_initial_offer(&mut self, req: &Request, downstream_req: &Request) {
        let Some(client_sdp_body) = sdp_body(&req.body) else {
            return;
        };
        let Ok(sdp) = sipora_sdp::session::parse_sdp(client_sdp_body) else {
            return;
        };
        let _ = self.dialog.uac_leg.apply_remote_offer(sdp);
        let Some(downstream_sdp_body) = sdp_body(&downstream_req.body) else {
            return;
        };
        let Ok(downstream_sdp) = sipora_sdp::session::parse_sdp(downstream_sdp_body) else {
            return;
        };
        let _ = self.dialog.uas_leg.apply_local_offer(downstream_sdp);
    }

    fn record_downstream_answer(&mut self, resp: &Response) {
        if !is_invite_success_or_provisional(resp) {
            return;
        }
        let Some(sdp_body) = sdp_body(&resp.body) else {
            return;
        };
        let Ok(sdp) = sipora_sdp::session::parse_sdp(sdp_body) else {
            return;
        };
        let _ = self.dialog.uas_leg.apply_remote_answer(sdp);
    }
}

impl B2buaLeg {
    fn new(call_id: String, peer_addr: SocketAddr) -> Self {
        Self {
            call_id: Some(call_id),
            local_tag: None,
            remote_tag: None,
            route_set: Vec::new(),
            last_local_cseq: None,
            last_remote_cseq: None,
            peer_addr,
        }
    }

    fn from_request(req: &Request, peer_addr: SocketAddr) -> Self {
        let mut leg = Self::new(req.call_id().unwrap_or_default().to_owned(), peer_addr);
        leg.local_tag = req.from_header().and_then(tag_from_name_addr);
        leg.remote_tag = req.to_header().and_then(tag_from_name_addr);
        leg.last_local_cseq = req.cseq().map(|c| c.seq);
        leg.route_set = route_set_from_headers(&req.headers);
        leg
    }

    fn update_from_response(&mut self, resp: &Response) {
        self.local_tag = first_name_addr_tag(&resp.headers, HeaderSide::From);
        self.remote_tag = first_name_addr_tag(&resp.headers, HeaderSide::To);
        self.last_remote_cseq = resp.cseq().map(|c| c.seq);
        self.route_set = route_set_from_headers(&resp.headers);
    }
}

fn sdp_body(body: &[u8]) -> Option<&str> {
    let sdp = std::str::from_utf8(body).ok()?;
    if !sdp.contains("v=0") {
        return None;
    }
    Some(sdp)
}

fn is_invite_success_or_provisional(resp: &Response) -> bool {
    resp.cseq()
        .is_some_and(|CSeq { method, .. }| *method == Method::Invite)
        && (resp.status.is_provisional() || resp.status.is_success())
}

fn route_set_from_headers(headers: &[Header]) -> Vec<String> {
    headers
        .iter()
        .filter_map(|header| match header {
            Header::Route(routes) | Header::RecordRoute(routes) => Some(routes.as_slice()),
            _ => None,
        })
        .flatten()
        .cloned()
        .collect()
}

fn tag_from_name_addr(name_addr: &NameAddr) -> Option<String> {
    name_addr.tag.clone()
}

#[derive(Debug, Clone, Copy)]
enum HeaderSide {
    From,
    To,
}

fn first_name_addr_tag(headers: &[Header], side: HeaderSide) -> Option<String> {
    headers.iter().find_map(|header| match (side, header) {
        (HeaderSide::From, Header::From(name_addr)) | (HeaderSide::To, Header::To(name_addr)) => {
            tag_from_name_addr(name_addr)
        }
        _ => None,
    })
}

fn tags_match(stored: Option<&str>, observed: Option<&str>) -> bool {
    match (stored, observed) {
        (Some(stored), Some(observed)) => stored == observed,
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::CodecPolicy;
    use sipora_sip::types::header::{CSeq, Header, NameAddr};
    use sipora_sip::types::message::{Request, Response, SipVersion};
    use sipora_sip::types::method::Method;
    use sipora_sip::types::status::StatusCode;

    fn client_addr() -> SocketAddr {
        "127.0.0.1:5062".parse().unwrap()
    }

    fn downstream_addr() -> SocketAddr {
        "127.0.0.1:5080".parse().unwrap()
    }

    fn initial_invite() -> Request {
        Request {
            method: Method::Invite,
            uri: "sip:bob@example.net".into(),
            version: SipVersion::V2_0,
            headers: vec![
                Header::From(NameAddr {
                    display_name: None,
                    uri: "sip:alice@example.com".into(),
                    tag: Some("from-tag".into()),
                    params: vec![],
                }),
                Header::To(NameAddr {
                    display_name: None,
                    uri: "sip:bob@example.net".into(),
                    tag: None,
                    params: vec![],
                }),
                Header::CallId("call-1@example.com".into()),
                Header::CSeq(CSeq {
                    seq: 42,
                    method: Method::Invite,
                }),
                Header::RecordRoute(vec!["<sip:edge.example.com;lr>".into()]),
            ],
            body: sample_sdp().as_bytes().to_vec(),
        }
    }

    fn options_request() -> Request {
        Request {
            method: Method::Options,
            uri: "sip:bob@example.net".into(),
            version: SipVersion::V2_0,
            headers: vec![
                Header::From(NameAddr {
                    display_name: None,
                    uri: "sip:alice@example.com".into(),
                    tag: Some("from-tag".into()),
                    params: vec![],
                }),
                Header::To(NameAddr {
                    display_name: None,
                    uri: "sip:bob@example.net".into(),
                    tag: None,
                    params: vec![],
                }),
                Header::CallId("options-1@example.com".into()),
                Header::CSeq(CSeq {
                    seq: 7,
                    method: Method::Options,
                }),
            ],
            body: Vec::new(),
        }
    }

    fn ringing_response() -> Response {
        Response {
            version: SipVersion::V2_0,
            status: StatusCode::RINGING,
            reason: "Ringing".into(),
            headers: vec![
                Header::From(NameAddr {
                    display_name: None,
                    uri: "sip:alice@example.com".into(),
                    tag: Some("from-tag".into()),
                    params: vec![],
                }),
                Header::To(NameAddr {
                    display_name: None,
                    uri: "sip:bob@example.net".into(),
                    tag: Some("to-tag".into()),
                    params: vec![],
                }),
                Header::CallId("call-1@example.com".into()),
                Header::CSeq(CSeq {
                    seq: 42,
                    method: Method::Invite,
                }),
                Header::RecordRoute(vec!["<sip:downstream.example.net;lr>".into()]),
            ],
            body: sample_sdp().as_bytes().to_vec(),
        }
    }

    fn ok_response(call_id: &str, cseq: CSeq) -> Response {
        Response {
            version: SipVersion::V2_0,
            status: StatusCode::OK,
            reason: "OK".into(),
            headers: vec![
                Header::From(NameAddr {
                    display_name: None,
                    uri: "sip:alice@example.com".into(),
                    tag: Some("from-tag".into()),
                    params: vec![],
                }),
                Header::To(NameAddr {
                    display_name: None,
                    uri: "sip:bob@example.net".into(),
                    tag: Some("to-tag".into()),
                    params: vec![],
                }),
                Header::CallId(call_id.into()),
                Header::CSeq(cseq),
            ],
            body: Vec::new(),
        }
    }

    fn sample_sdp() -> &'static str {
        "v=0\r\n\
         o=alice 1 1 IN IP4 127.0.0.1\r\n\
         s=-\r\n\
         c=IN IP4 127.0.0.1\r\n\
         t=0 0\r\n\
         m=audio 4000 RTP/AVP 0\r\n"
    }

    fn sdp_with_disallowed_codec() -> &'static str {
        "v=0\r\n\
         o=alice 1 1 IN IP4 127.0.0.1\r\n\
         s=-\r\n\
         c=IN IP4 127.0.0.1\r\n\
         t=0 0\r\n\
         m=audio 4000 RTP/AVP 0 18\r\n\
         a=rtpmap:0 PCMU/8000\r\n\
         a=rtpmap:18 G729/8000\r\n"
    }

    fn call_from_initial_invite() -> B2buaCall {
        let req = initial_invite();
        B2buaCall::from_initial_invite_pair(&req, &req, client_addr(), downstream_addr())
            .expect("invite should create call state")
    }

    #[test]
    fn initial_invite_creates_two_leg_call_state() {
        let call = call_from_initial_invite();

        assert_eq!(call.uac_leg.call_id.as_deref(), Some("call-1@example.com"));
        assert_eq!(call.uac_leg.local_tag.as_deref(), Some("from-tag"));
        assert_eq!(call.uac_leg.remote_tag, None);
        assert_eq!(call.uac_leg.last_local_cseq, Some(42));
        assert_eq!(
            call.uac_leg.route_set,
            vec!["<sip:edge.example.com;lr>".to_string()]
        );
        assert_eq!(call.uac_leg.peer_addr, client_addr());
        assert_eq!(call.uas_leg.peer_addr, downstream_addr());
        assert_eq!(call.uas_leg.local_tag.as_deref(), Some("from-tag"));
    }

    #[test]
    fn response_lookup_routes_to_client_and_updates_uas_leg() {
        let mut call = call_from_initial_invite();

        let relay_addr = call.client_addr_for_response(&ringing_response());

        assert_eq!(relay_addr, Some(client_addr()));
        assert_eq!(call.uas_leg.remote_tag.as_deref(), Some("to-tag"));
        assert_eq!(call.uas_leg.last_remote_cseq, Some(42));
        assert_eq!(
            call.uas_leg.route_set,
            vec!["<sip:downstream.example.net;lr>".to_string()]
        );
    }

    #[test]
    fn initial_invite_records_offer_answer_state() {
        let call = call_from_initial_invite();

        assert!(call.dialog.uac_leg.active_remote().is_some());
        assert!(call.dialog.uas_leg.active_local().is_some());
    }

    #[test]
    fn store_preserves_non_invite_response_relay() {
        let mut store = B2buaCallStore::default();
        let req = options_request();
        store.record_pending_request(&req, client_addr());

        let relay_addr = store.client_addr_for_response(&ok_response(
            "options-1@example.com",
            CSeq {
                seq: 7,
                method: Method::Options,
            },
        ));

        assert_eq!(relay_addr, Some(client_addr()));
    }

    #[test]
    fn store_falls_back_to_pending_when_call_id_matches_invite_call() {
        let mut store = B2buaCallStore::default();
        let invite = initial_invite();
        store.record_invite(&invite, &invite, client_addr(), downstream_addr());
        let mut options = options_request();
        set_call_id(&mut options.headers, "call-1@example.com");
        store.record_pending_request(&options, client_addr());

        let relay_addr = store.client_addr_for_response(&ok_response(
            "call-1@example.com",
            CSeq {
                seq: 7,
                method: Method::Options,
            },
        ));

        assert_eq!(relay_addr, Some(client_addr()));
    }

    #[test]
    fn mismatched_invite_cseq_response_is_rejected_without_mutating() {
        let mut call = call_from_initial_invite();
        let resp = ok_response(
            "call-1@example.com",
            CSeq {
                seq: 99,
                method: Method::Invite,
            },
        );

        let relay_addr = call.client_addr_for_response(&resp);

        assert_eq!(relay_addr, None);
        assert_eq!(call.uas_leg.remote_tag, None);
        assert_eq!(call.uas_leg.last_remote_cseq, None);
        assert!(call.dialog.uas_leg.active_remote().is_none());
    }

    #[test]
    fn mismatched_invite_local_tag_response_is_rejected() {
        let mut call = call_from_initial_invite();
        let mut resp = ringing_response();
        if let Header::From(from) = &mut resp.headers[0] {
            from.tag = Some("wrong-tag".into());
        }

        let relay_addr = call.client_addr_for_response(&resp);

        assert_eq!(relay_addr, None);
        assert_eq!(call.uas_leg.remote_tag, None);
    }

    #[test]
    fn uas_offer_answer_state_uses_filtered_downstream_sdp() {
        let mut client_req = initial_invite();
        client_req.body = sdp_with_disallowed_codec().as_bytes().to_vec();
        let mut downstream_req = client_req.clone();
        let (filtered_sdp, _removed) =
            CodecPolicy::new(vec!["PCMU".into()]).filter_sdp_codecs(sdp_with_disallowed_codec());
        downstream_req.body = filtered_sdp.into_bytes();

        let call = B2buaCall::from_initial_invite_pair(
            &client_req,
            &downstream_req,
            client_addr(),
            downstream_addr(),
        )
        .expect("invite should create call state");
        let uas_offer = call
            .dialog
            .uas_leg
            .active_local()
            .expect("UAS leg should record downstream offer");

        assert!(
            !uas_offer
                .medias
                .iter()
                .flat_map(|media| media.attributes.iter())
                .any(|attr| attr
                    .value
                    .as_deref()
                    .is_some_and(|value| value.contains("G729")))
        );
    }

    #[test]
    fn non_invite_does_not_create_initial_call_state() {
        let mut req = initial_invite();
        req.method = Method::Bye;

        let call =
            B2buaCall::from_initial_invite_pair(&req, &req, client_addr(), downstream_addr());

        assert!(call.is_none());
    }

    fn set_call_id(headers: &mut [Header], call_id: &str) {
        for header in headers {
            if let Header::CallId(existing) = header {
                *existing = call_id.to_string();
                return;
            }
        }
    }
}
