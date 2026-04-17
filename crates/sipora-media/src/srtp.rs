use crate::MediaError;

pub const DEFAULT_CIPHER: &str = "AES_128_CM_HMAC_SHA1_80";

pub struct SrtpPolicy {
    pub require_dtls_for_webrtc: bool,
    pub default_cipher: String,
    pub allow_rtp_fallback: bool,
}

impl Default for SrtpPolicy {
    fn default() -> Self {
        Self {
            require_dtls_for_webrtc: true,
            default_cipher: DEFAULT_CIPHER.to_owned(),
            allow_rtp_fallback: false,
        }
    }
}

impl SrtpPolicy {
    pub fn validate_offer(&self, sdp: &str, is_webrtc: bool) -> crate::Result<()> {
        if is_webrtc && self.require_dtls_for_webrtc {
            let has_dtls = sdp.contains("a=fingerprint:") && sdp.contains("a=setup:");
            if !has_dtls {
                return Err(MediaError::SrtpViolation(
                    "WebRTC client must use DTLS-SRTP, not SDES".into(),
                ));
            }
        }
        Ok(())
    }

    pub fn check_downgrade(&self, original_sdp: &str, new_sdp: &str) -> crate::Result<()> {
        if self.allow_rtp_fallback {
            return Ok(());
        }
        let had_crypto =
            original_sdp.contains("a=crypto:") || original_sdp.contains("a=fingerprint:");
        let has_crypto = new_sdp.contains("a=crypto:") || new_sdp.contains("a=fingerprint:");

        if had_crypto && !has_crypto {
            return Err(MediaError::SrtpViolation("SRTP downgrade forbidden".into()));
        }
        Ok(())
    }

    pub fn validate_cipher(&self, cipher: &str) -> crate::Result<()> {
        const ACCEPTABLE: &[&str] = &[
            "AES_128_CM_HMAC_SHA1_80",
            "AES_256_CM_HMAC_SHA1_80",
            "AEAD_AES_128_GCM",
            "AEAD_AES_256_GCM",
        ];
        if !ACCEPTABLE.iter().any(|c| c.eq_ignore_ascii_case(cipher)) {
            return Err(MediaError::SrtpViolation(format!(
                "unacceptable cipher: {cipher}"
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webrtc_requires_dtls() {
        let policy = SrtpPolicy::default();
        let no_dtls = "v=0\r\no=- 123 IN IP4 10.0.0.1\r\n";
        let with_dtls = "v=0\r\na=fingerprint:sha-256 AB:CD\r\na=setup:actpass\r\n";

        assert!(policy.validate_offer(no_dtls, true).is_err());
        assert!(policy.validate_offer(with_dtls, true).is_ok());
        assert!(policy.validate_offer(no_dtls, false).is_ok());
    }

    #[test]
    fn test_downgrade_detection() {
        let policy = SrtpPolicy::default();
        let srtp = "v=0\r\na=crypto:1 AES_128_CM_HMAC_SHA1_80\r\n";
        let rtp = "v=0\r\nm=audio 49170 RTP/AVP 0\r\n";

        assert!(policy.check_downgrade(srtp, rtp).is_err());
        assert!(policy.check_downgrade(srtp, srtp).is_ok());
    }

    #[test]
    fn test_cipher_validation() {
        let policy = SrtpPolicy::default();
        assert!(policy.validate_cipher("AES_128_CM_HMAC_SHA1_80").is_ok());
        assert!(policy.validate_cipher("AEAD_AES_256_GCM").is_ok());
        assert!(policy.validate_cipher("NULL_CIPHER").is_err());
    }
}
