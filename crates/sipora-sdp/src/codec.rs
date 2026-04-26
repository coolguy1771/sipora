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
///
/// By default [`CodecCapabilities::new`] sets [`CodecCapabilities::support_telephone_event`]
/// to `true` (RFC 4733 `telephone-event` / DTMF is accepted when offered). Turn it off with
/// `.with_telephone_event(false)` on the value returned from `new`, or build
/// a `CodecCapabilities { .. }` literal if you need full control.
#[derive(Debug, Clone)]
pub struct CodecCapabilities {
    codecs: Vec<RtpCodec>,
    support_telephone_event: bool,
}

impl CodecCapabilities {
    /// Builds capabilities from `codecs`; [`support_telephone_event`](Self::support_telephone_event) defaults to `true`.
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

/// Well-known static payload type mappings (RFC 3551 Tables 4–5).
///
/// Covers common audio and a few static video PTs used without `rtpmap`. **Intentionally
/// incomplete:** reserved PTs (e.g. 1–2), niche codecs (many DVI4/L16 variants), and most
/// static video assignments are omitted here because this stack targets an **audio-first
/// B2BUA** path where dynamic `a=rtpmap` is usual for video; add mappings as product needs
/// grow. Unknown PTs still return [`None`].
pub fn static_codec_for_pt(pt: u8) -> Option<(&'static str, u32)> {
    match pt {
        0 => Some(("PCMU", 8000)),
        3 => Some(("GSM", 8000)),
        4 => Some(("G723", 8000)),
        5 => Some(("DVI4", 8000)),
        6 => Some(("DVI4", 16000)),
        7 => Some(("LPC", 8000)),
        8 => Some(("PCMA", 8000)),
        9 => Some(("G722", 8000)),
        10 => Some(("L16", 44100)),
        11 => Some(("L16", 44100)),
        12 => Some(("QCELP", 8000)),
        13 => Some(("CN", 8000)),
        14 => Some(("MPA", 90000)),
        15 => Some(("G728", 8000)),
        16 => Some(("DVI4", 11025)),
        17 => Some(("DVI4", 22050)),
        18 => Some(("G729", 8000)),
        25 => Some(("CelB", 90000)),
        26 => Some(("JPEG", 90000)),
        31 => Some(("H261", 90000)),
        32 => Some(("MPV", 90000)),
        33 => Some(("MP2T", 90000)),
        34 => Some(("H263", 90000)),
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
///
/// Malformed `rtpmap` values are skipped (same as before when this returned `Ok`).
pub fn collect_rtpmaps(attributes: &[sdp_types::Attribute]) -> Vec<(u8, String, u32)> {
    let mut out = Vec::new();
    for a in attributes {
        if a.attribute == "rtpmap"
            && let Some(v) = &a.value
            && let Some(entry) = parse_rtpmap(v)
        {
            out.push(entry);
        }
    }
    out
}
