//! Push gateway wake hook and pending INVITE stash (Redis).

use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use fred::interfaces::ListInterface;
use fred::prelude::{Expiration, KeysInterface};
use serde::{Deserialize, Serialize};
use sipora_core::redis::RedisPool;
use sipora_core::redis_keys::{push_pending_index_key, push_pending_key};
use sipora_location::ContactBinding;
use tokio::net::UdpSocket;

use crate::ingress::{ProxyIngress, ReplyTarget};
use crate::message_sender::MessageSender;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum PendingReplySpec {
    Udp { peer: String },
    Ws { peer: String, connection_id: String },
    Tcp { peer: String },
}

#[derive(Serialize, Deserialize)]
struct PendingInviteEnvelope {
    reply: PendingReplySpec,
    body_b64: String,
}

#[derive(Serialize)]
struct PushWakeBody<'a> {
    provider: &'a str,
    prid: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    param: Option<&'a str>,
    #[serde(rename = "call-id")]
    call_id: &'a str,
}

/// Max pending INVITE Call-IDs per AOR (FIFO via list trim).
const PUSH_PENDING_INDEX_MAX: i64 = 31;

pub fn pending_reply_from_ingress(ingress: &ProxyIngress) -> PendingReplySpec {
    let peer = ingress.source.to_string();
    match &ingress.reply {
        ReplyTarget::Udp => PendingReplySpec::Udp { peer },
        ReplyTarget::Ws { connection_id, .. } => PendingReplySpec::Ws {
            peer,
            connection_id: connection_id.clone(),
        },
        ReplyTarget::Tcp { .. } => PendingReplySpec::Tcp { peer },
    }
}

/// Build ingress for replaying a stashed INVITE toward the original caller leg.
pub fn replay_ingress_from_spec(
    socket: Arc<UdpSocket>,
    sip_sender: Arc<dyn MessageSender>,
    tcp_pool: Option<Arc<sipora_transport::tcp_pool::TcpConnectionPool>>,
    spec: &PendingReplySpec,
) -> Option<ProxyIngress> {
    match spec {
        PendingReplySpec::Udp { peer } => {
            let addr = peer.parse().ok()?;
            Some(ProxyIngress::udp(socket, addr))
        }
        PendingReplySpec::Ws {
            peer,
            connection_id,
        } => {
            let addr = peer.parse().ok()?;
            Some(ProxyIngress::ws(
                socket,
                sip_sender,
                connection_id.clone(),
                addr,
            ))
        }
        PendingReplySpec::Tcp { peer } => {
            let addr = peer.parse().ok()?;
            let pool = tcp_pool?;
            Some(ProxyIngress::tcp_downstream(socket, pool, addr))
        }
    }
}

/// POST JSON to the configured push gateway (TLS via workspace `reqwest`).
pub async fn wake_device(
    client: &reqwest::Client,
    gateway_url: &str,
    timeout: std::time::Duration,
    auth_bearer: Option<&str>,
    binding: &ContactBinding,
    call_id: &str,
) -> anyhow::Result<()> {
    let prov = binding.pn_provider.as_deref().unwrap_or("");
    let prid = binding.pn_prid.as_deref().unwrap_or("");
    let body = PushWakeBody {
        provider: prov,
        prid,
        param: binding.pn_param.as_deref(),
        call_id,
    };
    let mut req = client.post(gateway_url).json(&body).timeout(timeout);
    if let Some(t) = auth_bearer {
        req = req.bearer_auth(t);
    }
    let r = req.send().await?;
    r.error_for_status()?;
    Ok(())
}

/// Store INVITE bytes + reply path for replay after REGISTER (TTL 30s) and index by AOR.
pub async fn stash_pending_invite(
    redis: &RedisPool,
    call_id: &str,
    invite_bytes: &[u8],
    reply: &PendingReplySpec,
    aor_domain: &str,
    aor_user: &str,
) -> anyhow::Result<()> {
    let key = push_pending_key(call_id);
    let idx = push_pending_index_key(aor_domain, aor_user);
    let env = PendingInviteEnvelope {
        reply: reply.clone(),
        body_b64: STANDARD.encode(invite_bytes),
    };
    let payload = serde_json::to_string(&env)?;
    let _: Option<String> = redis
        .set(&key, payload, Some(Expiration::EX(30)), None, false)
        .await?;
    let _: i64 = redis.rpush(&idx, call_id).await?;
    let _: () = redis.ltrim(&idx, 0, PUSH_PENDING_INDEX_MAX).await?;
    let _: bool = redis.expire(&idx, 30, None).await?;
    Ok(())
}

/// Remove and return stashed INVITE + reply spec for `call_id`, if present.
pub async fn take_pending_invite(
    redis: &RedisPool,
    call_id: &str,
) -> anyhow::Result<Option<(Vec<u8>, PendingReplySpec)>> {
    let key = push_pending_key(call_id);
    let raw: Option<String> = redis.get(&key).await?;
    let Some(raw) = raw else {
        return Ok(None);
    };
    let _: i64 = redis.del(&key).await?;
    if let Ok(env) = serde_json::from_str::<PendingInviteEnvelope>(&raw) {
        let bytes = STANDARD.decode(env.body_b64)?;
        return Ok(Some((bytes, env.reply)));
    }
    if STANDARD.decode(&raw).is_ok() {
        tracing::warn!(%call_id, "push_pending: legacy entry without reply path; dropping");
    } else {
        tracing::warn!(%call_id, "push_pending: corrupt entry; dropping");
    }
    Ok(None)
}

/// Pop pending Call-IDs for this AOR (oldest first) and load each stashed INVITE.
pub async fn drain_pending_invite_replays(
    redis: &RedisPool,
    domain: &str,
    user: &str,
) -> anyhow::Result<Vec<(Vec<u8>, PendingReplySpec)>> {
    let idx = push_pending_index_key(domain, user);
    let mut out = Vec::new();
    for _ in 0..=PUSH_PENDING_INDEX_MAX {
        let cid: Option<String> = redis.lpop(&idx, None).await?;
        let Some(call_id) = cid else {
            break;
        };
        if let Some(pair) = take_pending_invite(redis, &call_id).await? {
            out.push(pair);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_invite_envelope_roundtrip() {
        let env = PendingInviteEnvelope {
            reply: PendingReplySpec::Udp {
                peer: "192.0.2.1:5060".into(),
            },
            body_b64: STANDARD.encode(b"INVITE sip:a@b SIP/2.0\r\n\r\n"),
        };
        let s = serde_json::to_string(&env).unwrap();
        let back: PendingInviteEnvelope = serde_json::from_str(&s).unwrap();
        assert_eq!(back.reply, env.reply);
        assert_eq!(back.body_b64, env.body_b64);
    }
}
