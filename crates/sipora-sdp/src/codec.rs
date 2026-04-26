use crate::SdpError;

/// A single negotiable RTP codec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtpCodec {
    pub name: String,
    pub clock_rate: u32,
    pub channels: Option<u8>,
}

impl RtpCodec {
    pub fn new(name: impl Into<String>, clock_rate: u32) -> Self {
        Self {
            name: name.into(),
            clock_rate,
            channels: None,
        }
    }

    pub fn with_channels(mut self, ch: u8) -> Self {
        self.channels = Some(ch);
        self
    }
}

/// Local codec capability list ordered by preference (index 0 = most preferred).
#[derive(Debug, Clone)]
pub struct CodecCapabilities {
    codecs: Vec<RtpCodec>,
    support_telephone_event: bool,
}

impl CodecCapabilities {
    pub fn new(codecs: Vec<RtpCodec>) -> Self {
        Self {
            codecs,
            support_telephone_event: true,
        }
    }

    pub fn with_telephone_event(mut self, v: bool) -> Self {
        self.support_telephone_event = v;
        self
    }

    pub fn codecs(&self) -> &[RtpCodec] {
        &self.codecs
    }

    pub fn support_telephone_event(&self) -> bool {
        self.support_telephone_event
    }

    pub fn allows(&self, name: &str, clock_rate: u32) -> bool {
        self.codecs
            .iter()
            .any(|c| c.name.eq_ignore_ascii_case(name) && c.clock_rate == clock_rate)
    }
}

/// Well-known static payload type mappings (RFC 3551 Table 4).
pub fn static_codec_for_pt(pt: u8) -> Option<(&'static str, u32)> {
    match pt {
        0 => Some(("PCMU", 8000)),
        3 => Some(("GSM", 8000)),
        8 => Some(("PCMA", 8000)),
        9 => Some(("G722", 8000)),
        18 => Some(("G729", 8000)),
        _ => None,
    }
}

/// Parse an `a=rtpmap` attribute value (after "rtpmap:") into `(pt, name, clock_rate)`.
/// Expected format: `<PT> <name>/<rate>[/<channels>]`
pub fn parse_rtpmap(value: &str) -> Option<(u8, String, u32)> {
    let (pt_str, rest) = value.split_once(' ')?;
    let pt: u8 = pt_str.trim().parse().ok()?;
    let codec_str = rest.trim();
    let mut parts = codec_str.splitn(3, '/');
    let name = parts.next()?.to_owned();
    let clock_rate: u32 = parts.next()?.parse().ok()?;
    Some((pt, name, clock_rate))
}

/// Extract `(pt, name, clock_rate)` tuples from all `a=rtpmap` lines in a media section.
pub fn collect_rtpmaps(
    attributes: &[sdp_types::Attribute],
) -> Result<Vec<(u8, String, u32)>, SdpError> {
    let mut out = Vec::new();
    for a in attributes {
        if a.attribute == "rtpmap" {
            if let Some(v) = &a.value {
                if let Some(entry) = parse_rtpmap(v) {
                    out.push(entry);
                }
            }
        }
    }
    Ok(out)
}
