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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcePolicy {
    Remove,
    Force,
    Optional,
}

impl IcePolicy {
    pub fn as_ng_str(self) -> &'static str {
        match self {
            Self::Remove => "remove",
            Self::Force => "force",
            Self::Optional => "optional",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DtlsPolicy {
    Passive,
    Off,
}

impl DtlsPolicy {
    pub fn as_ng_str(self) -> &'static str {
        match self {
            Self::Passive => "passive",
            Self::Off => "off",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtpEnginePolicy {
    pub ice: IcePolicy,
    pub dtls: DtlsPolicy,
}

impl RtpEnginePolicy {
    pub fn classic_udp() -> Self {
        Self {
            ice: IcePolicy::Remove,
            dtls: DtlsPolicy::Passive,
        }
    }
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
        Self::build_offer_with_policy(call_id, sdp, from_tag, &RtpEnginePolicy::classic_udp())
    }

    pub fn build_offer_with_policy(
        call_id: &str,
        sdp: &str,
        from_tag: &str,
        policy: &RtpEnginePolicy,
    ) -> NgCommand {
        let mut params = HashMap::new();
        params.insert("sdp".into(), sdp.to_owned());
        params.insert("from-tag".into(), from_tag.to_owned());
        apply_policy_params(&mut params, policy);
        NgCommand {
            command: "offer".into(),
            call_id: call_id.to_owned(),
            params,
        }
    }

    pub fn build_answer(call_id: &str, sdp: &str, from_tag: &str, to_tag: &str) -> NgCommand {
        Self::build_answer_with_policy(
            call_id,
            sdp,
            from_tag,
            to_tag,
            &RtpEnginePolicy::classic_udp(),
        )
    }

    pub fn build_answer_with_policy(
        call_id: &str,
        sdp: &str,
        from_tag: &str,
        to_tag: &str,
        policy: &RtpEnginePolicy,
    ) -> NgCommand {
        let mut params = HashMap::new();
        params.insert("sdp".into(), sdp.to_owned());
        params.insert("from-tag".into(), from_tag.to_owned());
        params.insert("to-tag".into(), to_tag.to_owned());
        apply_policy_params(&mut params, policy);
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

fn apply_policy_params(params: &mut HashMap<String, String>, policy: &RtpEnginePolicy) {
    params.insert("ICE".into(), policy.ice.as_ng_str().into());
    params.insert("DTLS".into(), policy.dtls.as_ng_str().into());
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

#[cfg(test)]
mod tests {
    use super::*;

    const SDP: &str = "v=0\r\nm=audio 4000 RTP/AVP 0\r\n";

    #[test]
    fn classic_policy_preserves_offer_ice_and_dtls_params() {
        let cmd = RtpEngineClient::build_offer("call-1", SDP, "from-1");

        assert_eq!(cmd.params.get("ICE").map(String::as_str), Some("remove"));
        assert_eq!(cmd.params.get("DTLS").map(String::as_str), Some("passive"));
    }

    #[test]
    fn classic_policy_adds_answer_ice_and_dtls_params() {
        let cmd = RtpEngineClient::build_answer("call-1", SDP, "from-1", "to-1");

        assert_eq!(cmd.params.get("ICE").map(String::as_str), Some("remove"));
        assert_eq!(cmd.params.get("DTLS").map(String::as_str), Some("passive"));
    }

    #[test]
    fn ice_capable_policy_can_keep_candidates_with_passive_dtls() {
        let policy = RtpEnginePolicy {
            ice: IcePolicy::Optional,
            dtls: DtlsPolicy::Passive,
        };

        let cmd = RtpEngineClient::build_offer_with_policy("call-1", SDP, "from-1", &policy);

        assert_eq!(cmd.params.get("ICE").map(String::as_str), Some("optional"));
        assert_eq!(cmd.params.get("DTLS").map(String::as_str), Some("passive"));
    }
}
