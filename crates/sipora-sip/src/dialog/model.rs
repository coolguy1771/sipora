use crate::types::header::Header;
use crate::types::message::{Request, Response};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DialogId {
    pub call_id: String,
    pub local_tag: String,
    pub remote_tag: String,
}

#[derive(Debug, Clone)]
pub struct Dialog {
    pub id: DialogId,
    pub local_uri: String,
    pub remote_uri: String,
    pub remote_target: String,
    pub route_set: Vec<String>,
    pub local_seq: Option<u32>,
    pub remote_seq: Option<u32>,
    pub secure: bool,
}

impl Dialog {
    pub fn from_uac_response(req: &Request, resp: &Response) -> Option<Self> {
        let call_id = req.call_id()?.to_owned();
        let local_tag = req.from_header()?.tag.clone().unwrap_or_default();
        let remote_tag = extract_to_tag(&resp.headers).unwrap_or_default();

        let local_uri = req.from_header()?.uri.clone();
        let remote_uri = req.to_header()?.uri.clone();
        let remote_target = resp
            .contacts()
            .first()
            .map(|c| c.uri.clone())
            .unwrap_or_else(|| remote_uri.clone());

        let route_set: Vec<String> = collect_record_routes(&resp.headers)
            .into_iter()
            .rev()
            .collect();

        Some(Self {
            id: DialogId {
                call_id,
                local_tag,
                remote_tag,
            },
            local_uri,
            remote_uri,
            remote_target,
            route_set,
            local_seq: req.cseq().map(|cs| cs.seq),
            remote_seq: None,
            secure: req.uri.starts_with("sips:"),
        })
    }

    pub fn from_uas_request(req: &Request) -> Option<Self> {
        let call_id = req.call_id()?.to_owned();
        let remote_tag = req.from_header()?.tag.clone().unwrap_or_default();
        let local_tag = String::new();

        let remote_uri = req.from_header()?.uri.clone();
        let local_uri = req.to_header()?.uri.clone();
        let remote_target = req
            .contacts()
            .first()
            .map(|c| c.uri.clone())
            .unwrap_or_else(|| remote_uri.clone());

        let route_set = collect_record_routes(&req.headers);

        Some(Self {
            id: DialogId {
                call_id,
                local_tag,
                remote_tag,
            },
            local_uri,
            remote_uri,
            remote_target,
            route_set,
            local_seq: None,
            remote_seq: req.cseq().map(|cs| cs.seq),
            secure: req.uri.starts_with("sips:"),
        })
    }
}

fn extract_to_tag(headers: &[Header]) -> Option<String> {
    headers.iter().find_map(|h| match h {
        Header::To(na) => na.tag.clone(),
        _ => None,
    })
}

fn collect_record_routes(headers: &[Header]) -> Vec<String> {
    headers
        .iter()
        .filter_map(|h| match h {
            Header::RecordRoute(routes) => Some(routes.clone()),
            _ => None,
        })
        .flatten()
        .collect()
}
