use sipora_sip::types::header::Header;
use sipora_sip::types::message::{Request, Response};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DialogKey {
    pub call_id: String,
    pub from_tag: String,
    pub to_tag: String,
}

impl DialogKey {
    fn reversed(&self) -> Self {
        Self {
            call_id: self.call_id.clone(),
            from_tag: self.to_tag.clone(),
            to_tag: self.from_tag.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DialogState {
    pub route_set: Vec<String>,
    pub remote_target: String,
    pub cseq: u32,
    pub caller_addr: SocketAddr,
    pub callee_addr: SocketAddr,
    pub session_expires: Option<u32>,
}

pub type DialogTable = Arc<RwLock<HashMap<DialogKey, DialogState>>>;

pub fn new_dialog_table() -> DialogTable {
    Arc::new(RwLock::new(HashMap::new()))
}

pub async fn insert_dialog_from_response(
    table: &DialogTable,
    response: &Response,
    caller_addr: SocketAddr,
    callee_addr: SocketAddr,
) -> Option<DialogKey> {
    let key = response_dialog_key(response)?;
    let state = DialogState {
        route_set: response_route_set(response),
        remote_target: response_remote_target(response)?,
        cseq: response.cseq()?.seq,
        caller_addr,
        callee_addr,
        session_expires: None,
    };
    table.write().await.insert(key.clone(), state);
    Some(key)
}

pub async fn dialog_for_request(
    table: &DialogTable,
    request: &Request,
) -> Option<(DialogKey, DialogState)> {
    let key = request_dialog_key(request)?;
    let dialogs = table.read().await;
    dialogs
        .get(&key)
        .cloned()
        .map(|state| (key.clone(), state))
        .or_else(|| {
            let reversed = key.reversed();
            dialogs
                .get(&reversed)
                .cloned()
                .map(|state| (reversed, state))
        })
}

fn response_dialog_key(response: &Response) -> Option<DialogKey> {
    let call_id = response.call_id()?.to_owned();
    let from_tag = response.headers.iter().find_map(from_tag)?;
    let to_tag = response.headers.iter().find_map(to_tag)?;
    Some(DialogKey {
        call_id,
        from_tag,
        to_tag,
    })
}

fn request_dialog_key(request: &Request) -> Option<DialogKey> {
    let call_id = request.call_id()?.to_owned();
    let from_tag = request.from_header()?.tag.clone()?;
    let to_tag = request.to_header()?.tag.clone()?;
    Some(DialogKey {
        call_id,
        from_tag,
        to_tag,
    })
}

fn response_route_set(response: &Response) -> Vec<String> {
    response
        .headers
        .iter()
        .filter_map(|header| match header {
            Header::RecordRoute(routes) => Some(routes.clone()),
            _ => None,
        })
        .flatten()
        .rev()
        .collect()
}

fn response_remote_target(response: &Response) -> Option<String> {
    response
        .contacts()
        .first()
        .map(|contact| contact.uri.clone())
}

fn from_tag(header: &Header) -> Option<String> {
    match header {
        Header::From(name_addr) => name_addr.tag.clone(),
        _ => None,
    }
}

fn to_tag(header: &Header) -> Option<String> {
    match header {
        Header::To(name_addr) => name_addr.tag.clone(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sipora_sip::types::header::{CSeq, ContactValue, NameAddr};
    use sipora_sip::types::message::SipVersion;
    use sipora_sip::types::method::Method;
    use sipora_sip::types::status::StatusCode;

    #[tokio::test]
    async fn stores_dialog_from_invite_success_response() {
        let table = new_dialog_table();
        let caller = "127.0.0.1:5060".parse().unwrap();
        let callee = "127.0.0.1:5070".parse().unwrap();

        let key = insert_dialog_from_response(&table, &success_response(), caller, callee)
            .await
            .unwrap();

        let state = table.read().await[&key].clone();
        assert_eq!(state.remote_target, "sip:bob@callee.example.com");
        assert_eq!(state.route_set, vec!["<sip:edge.example.com;lr>"]);
        assert_eq!(state.cseq, 1);
        assert_eq!(state.caller_addr, caller);
        assert_eq!(state.callee_addr, callee);
        assert_eq!(state.session_expires, None);
    }

    fn success_response() -> Response {
        Response {
            version: SipVersion::V2_0,
            status: StatusCode::OK,
            reason: "OK".to_string(),
            headers: vec![
                Header::From(NameAddr {
                    display_name: None,
                    uri: "sip:alice@example.com".to_string(),
                    tag: Some("from-tag".to_string()),
                    params: vec![],
                }),
                Header::To(NameAddr {
                    display_name: None,
                    uri: "sip:bob@example.com".to_string(),
                    tag: Some("to-tag".to_string()),
                    params: vec![],
                }),
                Header::CallId("call-1".to_string()),
                Header::CSeq(CSeq {
                    seq: 1,
                    method: Method::Invite,
                }),
                Header::Contact(vec![ContactValue {
                    uri: "sip:bob@callee.example.com".to_string(),
                    q: None,
                    expires: None,
                    params: vec![],
                }]),
                Header::RecordRoute(vec!["<sip:edge.example.com;lr>".to_string()]),
            ],
            body: Vec::new(),
        }
    }
}
