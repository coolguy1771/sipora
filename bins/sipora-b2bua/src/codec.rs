//! Codec allowlist and SDP filtering for negotiated media.

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
