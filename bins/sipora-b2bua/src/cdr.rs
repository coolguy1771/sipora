//! CDR helpers for the B2BUA.

use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct CallDetailRecord {
    pub id: Uuid,
    pub correlation_id: Uuid,
    pub leg: char,
    pub from_uri: String,
    pub to_uri: String,
    pub setup_at: DateTime<Utc>,
    pub answered_at: Option<DateTime<Utc>>,
    pub ended_at: Option<DateTime<Utc>>,
    pub duration_s: Option<i64>,
    pub result_code: u16,
    pub codec: Option<String>,
    pub rtp_loss_pct: Option<f64>,
    pub rtp_jitter_ms: Option<f64>,
    pub srtp_cipher: Option<String>,
    pub media_ip: Option<String>,
    pub proxy_node: Option<String>,
}

impl CallDetailRecord {
    pub fn new_leg(
        correlation_id: Uuid,
        leg: char,
        from_uri: &str,
        to_uri: &str,
        setup_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            correlation_id,
            leg,
            from_uri: from_uri.to_owned(),
            to_uri: to_uri.to_owned(),
            setup_at,
            answered_at: None,
            ended_at: None,
            duration_s: None,
            result_code: 0,
            codec: None,
            rtp_loss_pct: None,
            rtp_jitter_ms: None,
            srtp_cipher: None,
            media_ip: None,
            proxy_node: None,
        }
    }

    pub fn complete(&mut self, result_code: u16, ended_at: DateTime<Utc>) {
        self.ended_at = Some(ended_at);
        self.result_code = result_code;
        if let Some(answered) = self.answered_at {
            self.duration_s = Some((ended_at - answered).num_seconds());
        }
    }

    pub fn set_media_stats(
        &mut self,
        codec: &str,
        loss_pct: f64,
        jitter_ms: f64,
        cipher: &str,
        media_ip: &str,
    ) {
        self.codec = Some(codec.to_owned());
        self.rtp_loss_pct = Some(loss_pct);
        self.rtp_jitter_ms = Some(jitter_ms);
        self.srtp_cipher = Some(cipher.to_owned());
        self.media_ip = Some(media_ip.to_owned());
    }

    pub fn to_data_cdr(&self) -> sipora_data::cdr::CdrRecord {
        sipora_data::cdr::CdrRecord {
            id: self.id,
            correlation_id: self.correlation_id,
            leg: self.leg,
            from_uri: self.from_uri.clone(),
            to_uri: self.to_uri.clone(),
            setup_at: self.setup_at,
            answered_at: self.answered_at,
            ended_at: self.ended_at,
            duration_s: self.duration_s,
            result_code: self.result_code,
            codec: self.codec.clone(),
            rtp_loss_pct: self.rtp_loss_pct,
            rtp_jitter_ms: self.rtp_jitter_ms,
            srtp_cipher: self.srtp_cipher.clone(),
            media_ip: self.media_ip.clone(),
            proxy_node: self.proxy_node.clone(),
            hash_chain: None,
        }
    }

    pub fn log_snapshot(&self, tag: &str) {
        tracing::debug!(
            tag,
            id = %self.id,
            correlation_id = %self.correlation_id,
            leg = ?self.leg,
            from_uri = %self.from_uri,
            to_uri = %self.to_uri,
            setup_at = %self.setup_at,
            answered_at = ?self.answered_at,
            ended_at = ?self.ended_at,
            duration_s = ?self.duration_s,
            result_code = self.result_code,
            codec = ?self.codec,
            rtp_loss_pct = ?self.rtp_loss_pct,
            rtp_jitter_ms = ?self.rtp_jitter_ms,
            srtp_cipher = ?self.srtp_cipher,
            media_ip = ?self.media_ip,
            proxy_node = ?self.proxy_node,
            "cdr leg snapshot"
        );
    }
}

pub fn generate_call_cdrs(
    from_uri: &str,
    to_uri: &str,
    setup_at: DateTime<Utc>,
) -> (CallDetailRecord, CallDetailRecord) {
    let correlation_id = Uuid::new_v4();
    let a_leg = CallDetailRecord::new_leg(correlation_id, 'A', from_uri, to_uri, setup_at);
    let b_leg = CallDetailRecord::new_leg(correlation_id, 'B', from_uri, to_uri, setup_at);
    (a_leg, b_leg)
}
