// rtpengine contract:
// - rtpengine rewrites: a=candidate, a=ice-ufrag, a=ice-pwd, a=fingerprint (if terminating DTLS)
// - sipora-b2bua must preserve: o=, s=, t=, a=sendrecv/sendonly, a=fmtp, codec list order
// - sipora-b2bua must NOT strip: a=rtcp, b=AS, b=RR, b=RS, telephone-event

//! Codec allowlist, SDP filtering, and B2BUA offer/answer state for negotiated media.

#[derive(Clone)]
pub struct CodecPolicy {
    allowed: Vec<String>,
}

impl CodecPolicy {
    pub fn new(allowed: Vec<String>) -> Self {
        Self { allowed }
    }

    pub fn is_allowed(&self, codec: &str) -> bool {
        self.allowed.iter().any(|c| c.eq_ignore_ascii_case(codec))
    }

    pub fn filter_sdp_codecs(&self, sdp: &str) -> (String, Vec<String>) {
        let mut filtered_lines = Vec::new();
        let mut removed = Vec::new();

        for line in sdp.lines() {
            if line.starts_with("a=rtpmap:") {
                if let Some(name) = extract_codec_name(line) {
                    if self.is_allowed(&name) {
                        filtered_lines.push(line.to_owned());
                    } else {
                        removed.push(name);
                    }
                } else {
                    filtered_lines.push(line.to_owned());
                }
            } else {
                filtered_lines.push(line.to_owned());
            }
        }

        (filtered_lines.join("\r\n"), removed)
    }
}

/// Two-leg offer/answer state for one B2BUA dialog.
///
/// `uac_leg` tracks the offer/answer state toward the user agent client (caller);
/// `uas_leg` tracks the state toward the user agent server (callee / rtpengine).
/// The two legs are independent — media is not simply forwarded between them.
#[allow(dead_code)]
pub struct B2buaDialog {
    pub uac_leg: sipora_sdp::offer_answer::OfferAnswerMachine,
    pub uas_leg: sipora_sdp::offer_answer::OfferAnswerMachine,
}

#[allow(dead_code)]
impl B2buaDialog {
    pub fn new() -> Self {
        Self {
            uac_leg: sipora_sdp::offer_answer::OfferAnswerMachine::new(),
            uas_leg: sipora_sdp::offer_answer::OfferAnswerMachine::new(),
        }
    }
}

impl Default for B2buaDialog {
    fn default() -> Self {
        Self::new()
    }
}

fn extract_codec_name(rtpmap_line: &str) -> Option<String> {
    let value = rtpmap_line.strip_prefix("a=rtpmap:")?;
    let after_pt = value.split_whitespace().nth(1)?;
    let codec = after_pt.split('/').next()?;
    Some(codec.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_codec_filtering() {
        let policy = CodecPolicy::new(vec![
            "opus".into(),
            "G722".into(),
            "PCMU".into(),
            "PCMA".into(),
        ]);
        assert!(policy.is_allowed("opus"));
        assert!(policy.is_allowed("PCMU"));
        assert!(!policy.is_allowed("G729"));
    }

    #[test]
    fn test_extract_codec_name() {
        assert_eq!(
            extract_codec_name("a=rtpmap:111 opus/48000/2"),
            Some("opus".into())
        );
        assert_eq!(
            extract_codec_name("a=rtpmap:9 G722/8000"),
            Some("G722".into())
        );
    }
}
