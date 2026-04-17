use std::collections::HashMap;
use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub struct NgCommand {
    pub command: String,
    pub call_id: String,
    pub params: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct NgResponse {
    pub result: String,
    pub sdp: Option<String>,
    pub error_reason: Option<String>,
}

pub struct RtpEngineClient {
    endpoint: SocketAddr,
}

impl RtpEngineClient {
    pub fn new(endpoint: SocketAddr) -> Self {
        Self { endpoint }
    }

    pub fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }

    pub fn build_offer(call_id: &str, sdp: &str, from_tag: &str) -> NgCommand {
        let mut params = HashMap::new();
        params.insert("sdp".into(), sdp.to_owned());
        params.insert("from-tag".into(), from_tag.to_owned());
        params.insert("ICE".into(), "remove".into());
        params.insert("DTLS".into(), "passive".into());
        NgCommand {
            command: "offer".into(),
            call_id: call_id.to_owned(),
            params,
        }
    }

    pub fn build_answer(call_id: &str, sdp: &str, from_tag: &str, to_tag: &str) -> NgCommand {
        let mut params = HashMap::new();
        params.insert("sdp".into(), sdp.to_owned());
        params.insert("from-tag".into(), from_tag.to_owned());
        params.insert("to-tag".into(), to_tag.to_owned());
        NgCommand {
            command: "answer".into(),
            call_id: call_id.to_owned(),
            params,
        }
    }

    pub fn build_delete(call_id: &str, from_tag: &str) -> NgCommand {
        let mut params = HashMap::new();
        params.insert("from-tag".into(), from_tag.to_owned());
        NgCommand {
            command: "delete".into(),
            call_id: call_id.to_owned(),
            params,
        }
    }

    pub fn build_query(call_id: &str) -> NgCommand {
        NgCommand {
            command: "query".into(),
            call_id: call_id.to_owned(),
            params: HashMap::new(),
        }
    }

    pub fn encode_command(cookie: &str, cmd: &NgCommand) -> Vec<u8> {
        let mut encoded = format!("{cookie} d");
        encoded.push_str(&format!("7:command{}:{}", cmd.command.len(), cmd.command));
        encoded.push_str(&format!("7:call-id{}:{}", cmd.call_id.len(), cmd.call_id));
        for (k, v) in &cmd.params {
            encoded.push_str(&format!("{}:{}{}:{}", k.len(), k, v.len(), v));
        }
        encoded.push('e');
        encoded.into_bytes()
    }

    pub fn parse_response(data: &[u8]) -> Option<NgResponse> {
        let s = String::from_utf8_lossy(data);
        let dict_start = s.find('d')?;
        let body = &s[dict_start..];

        let result = extract_bencode_value(body, "result")?;
        let sdp = extract_bencode_value(body, "sdp");
        let error_reason = extract_bencode_value(body, "error-reason");

        Some(NgResponse {
            result,
            sdp,
            error_reason,
        })
    }
}

fn extract_bencode_value(data: &str, key: &str) -> Option<String> {
    let key_encoded = format!("{}:{}", key.len(), key);
    let pos = data.find(&key_encoded)?;
    let after_key = &data[pos + key_encoded.len()..];

    let colon_pos = after_key.find(':')?;
    let len_str = &after_key[..colon_pos];
    let len: usize = len_str.parse().ok()?;
    let value = &after_key[colon_pos + 1..colon_pos + 1 + len];
    Some(value.to_owned())
}

#[derive(Debug, Clone)]
pub struct MediaStats {
    pub packet_loss_pct: f64,
    pub jitter_ms: f64,
    pub packets_sent: u64,
    pub packets_recv: u64,
}
