use sdp_types::Session;
use thiserror::Error;

use crate::codec::CodecCapabilities;
use crate::negotiate::negotiate_sdp_answer;

#[derive(Debug, Error)]
pub enum OaError {
    #[error("invalid state transition: {0}")]
    InvalidTransition(&'static str),
    #[error("no remote offer to answer")]
    NoOffer,
    #[error("SDP negotiation failed: {0}")]
    Negotiate(String),
}

/// Offer/answer state (RFC 3264 §4).
pub enum OaState {
    Idle,
    LocalOffer(Session),
    RemoteOffer(Session),
    Stable { local: Session, remote: Session },
}

/// Per-leg offer/answer state machine.
///
/// A B2BUA has two independent machines — one toward the UAC and one toward the
/// UAS.  Neither side's media state is simply forwarded from the other.
pub struct OfferAnswerMachine {
    state: OaState,
    version: u64,
}

impl OfferAnswerMachine {
    pub fn new() -> Self {
        Self {
            state: OaState::Idle,
            version: 0,
        }
    }

    /// Record a local offer we are about to send.
    pub fn apply_local_offer(&mut self, offer: Session) -> Result<(), OaError> {
        match &self.state {
            OaState::Idle | OaState::Stable { .. } => {
                self.state = OaState::LocalOffer(offer);
                Ok(())
            }
            _ => Err(OaError::InvalidTransition(
                "apply_local_offer: must be Idle or Stable",
            )),
        }
    }

    /// Record a remote answer to our pending local offer; transitions to Stable.
    pub fn apply_remote_answer(&mut self, answer: Session) -> Result<Session, OaError> {
        let offer = match std::mem::replace(&mut self.state, OaState::Idle) {
            OaState::LocalOffer(o) => o,
            other => {
                self.state = other;
                return Err(OaError::InvalidTransition(
                    "apply_remote_answer: must be in LocalOffer",
                ));
            }
        };
        self.state = OaState::Stable {
            local: offer,
            remote: answer.clone(),
        };
        Ok(answer)
    }

    /// Record an incoming remote offer; transitions to RemoteOffer.
    pub fn apply_remote_offer(&mut self, offer: Session) -> Result<(), OaError> {
        match &self.state {
            OaState::Idle | OaState::Stable { .. } => {
                self.state = OaState::RemoteOffer(offer);
                Ok(())
            }
            _ => Err(OaError::InvalidTransition(
                "apply_remote_offer: must be Idle or Stable",
            )),
        }
    }

    /// Generate an SDP answer to the current remote offer and transition to Stable.
    ///
    /// `caps` controls codec selection. Increments the local `o=` version on each call.
    pub fn generate_answer(&mut self, caps: &CodecCapabilities) -> Result<Session, OaError> {
        let offer = match std::mem::replace(&mut self.state, OaState::Idle) {
            OaState::RemoteOffer(o) => o,
            other => {
                self.state = other;
                return Err(OaError::NoOffer);
            }
        };
        self.version += 1;
        let answer = negotiate_sdp_answer(&offer, caps, self.version)
            .map_err(|e| OaError::Negotiate(e.to_string()))?;
        self.state = OaState::Stable {
            local: answer.clone(),
            remote: offer,
        };
        Ok(answer)
    }

    pub fn active_local(&self) -> Option<&Session> {
        match &self.state {
            OaState::Stable { local, .. } | OaState::LocalOffer(local) => Some(local),
            _ => None,
        }
    }

    pub fn active_remote(&self) -> Option<&Session> {
        match &self.state {
            OaState::Stable { remote, .. } | OaState::RemoteOffer(remote) => Some(remote),
            _ => None,
        }
    }
}

impl Default for OfferAnswerMachine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{CodecCapabilities, RtpCodec};
    use crate::session::parse_sdp;

    fn caps() -> CodecCapabilities {
        CodecCapabilities::new(vec![RtpCodec::new("opus", 48000).with_channels(2)])
    }

    const OFFER_SDP: &str = "\
v=0\r\n\
o=alice 1 1 IN IP4 192.0.2.1\r\n\
s=-\r\n\
t=0 0\r\n\
m=audio 49170 RTP/AVP 111\r\n\
a=rtpmap:111 opus/48000/2\r\n\
a=sendrecv\r\n";

    #[test]
    fn idle_to_remote_offer_to_stable() {
        let mut m = OfferAnswerMachine::new();
        let offer = parse_sdp(OFFER_SDP).unwrap();
        m.apply_remote_offer(offer).unwrap();
        let answer = m.generate_answer(&caps()).unwrap();
        assert_eq!(answer.origin.sess_version, 1, "version incremented");
        // state should now be Stable
        assert!(m.active_local().is_some());
        assert!(m.active_remote().is_some());
    }

    #[test]
    fn reinvite_bumps_version() {
        let mut m = OfferAnswerMachine::new();
        let offer = parse_sdp(OFFER_SDP).unwrap();
        m.apply_remote_offer(offer.clone()).unwrap();
        let a1 = m.generate_answer(&caps()).unwrap();
        // re-INVITE
        m.apply_remote_offer(offer).unwrap();
        let a2 = m.generate_answer(&caps()).unwrap();
        assert_eq!(a1.origin.sess_version, 1);
        assert_eq!(a2.origin.sess_version, 2, "re-INVITE bumps version");
    }

    #[test]
    fn invalid_transition_returns_error() {
        let mut m = OfferAnswerMachine::new();
        // Cannot call apply_remote_answer without a pending local offer
        let offer = parse_sdp(OFFER_SDP).unwrap();
        let result = m.apply_remote_answer(offer);
        assert!(result.is_err());
    }
}
