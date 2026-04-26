use sdp_types::{Attribute, Media, Session};

use crate::SdpError;
use crate::codec::{CodecCapabilities, collect_rtpmaps, static_codec_for_pt};

/// Passthrough attributes copied verbatim from offer to answer (RFC 5764, RFC 8839).
const PASSTHROUGH: &[&str] = &[
    "fingerprint",
    "setup",
    "ice-ufrag",
    "ice-pwd",
    "ice-options",
    "candidate",
    "rtcp",
    "mid",
    "extmap",
    "msid",
    "ssrc",
    "group",
];

/// Generate an SDP answer for `offer` intersecting with `caps`.
///
/// Sets `o=` sess_version to `answer_version`.  All media sections from the offer
/// are answered; sections where no codec matches have their port set to 0 (rejected).
pub fn negotiate_sdp_answer(
    offer: &Session,
    caps: &CodecCapabilities,
    answer_version: u64,
) -> Result<Session, SdpError> {
    let mut answer = offer.clone();
    answer.origin.sess_version = answer_version;
    answer.session_name = "-".to_owned();
    // Strip session-level direction — direction is per-media in answers.
    answer.attributes.retain(|a| !is_direction(&a.attribute));

    answer.medias = offer
        .medias
        .iter()
        .map(|m| negotiate_answer_media(m, caps))
        .collect();

    Ok(answer)
}

/// Produce one answer m-section for a given offer m-section.
fn negotiate_answer_media(offer_m: &Media, caps: &CodecCapabilities) -> Media {
    let offered_pts: Vec<u8> = offer_m
        .fmt
        .split_whitespace()
        .filter_map(|s| s.parse().ok())
        .collect();

    let rtpmaps = collect_rtpmaps(&offer_m.attributes).unwrap_or_default();

    let accepted = select_codecs(&offered_pts, &rtpmaps, caps);
    let port = if accepted.is_empty() { 0 } else { offer_m.port };

    let fmt = if accepted.is_empty() {
        offer_m.fmt.clone()
    } else {
        accepted
            .iter()
            .map(|pt| pt.to_string())
            .collect::<Vec<_>>()
            .join(" ")
    };

    let offer_dir = offer_direction(offer_m);
    let answer_dir = flip_direction(offer_dir);

    let mut attrs: Vec<Attribute> = Vec::new();
    attrs.push(Attribute {
        attribute: answer_dir.to_owned(),
        value: None,
    });

    // rtpmap for accepted PTs (in accepted order)
    for &pt in &accepted {
        if let Some(a) = offer_m.attributes.iter().find(|a| {
            a.attribute == "rtpmap"
                && a.value
                    .as_deref()
                    .unwrap_or("")
                    .starts_with(&format!("{pt} "))
        }) {
            attrs.push(a.clone());
        }
    }
    // fmtp for accepted PTs
    for &pt in &accepted {
        if let Some(a) = offer_m.attributes.iter().find(|a| {
            a.attribute == "fmtp"
                && a.value
                    .as_deref()
                    .unwrap_or("")
                    .starts_with(&format!("{pt} "))
        }) {
            attrs.push(a.clone());
        }
    }
    // Passthrough attributes
    for a in &offer_m.attributes {
        if PASSTHROUGH.contains(&a.attribute.as_str()) {
            attrs.push(a.clone());
        }
    }

    Media {
        media: offer_m.media.clone(),
        port,
        num_ports: offer_m.num_ports,
        proto: offer_m.proto.clone(),
        fmt,
        media_title: offer_m.media_title.clone(),
        connections: offer_m.connections.clone(),
        bandwidths: offer_m.bandwidths.clone(),
        key: offer_m.key.clone(),
        attributes: attrs,
    }
}

/// Select accepted payload types from an offer, in local-capability-preference order.
///
/// Walk caps in preference order so the answer reflects our priority, not the offer's.
/// telephone-event is appended last if offered and locally supported.
/// Static PTs (no rtpmap) are matched via RFC 3551 well-known table.
fn select_codecs(
    offered_pts: &[u8],
    rtpmaps: &[(u8, String, u32)],
    caps: &CodecCapabilities,
) -> Vec<u8> {
    let mut accepted: Vec<u8> = Vec::new();

    // Phase 1: dynamic codecs — walk caps in preference order.
    for cap in caps.codecs() {
        if let Some((pt, _, _)) = rtpmaps
            .iter()
            .find(|(_, name, rate)| name.eq_ignore_ascii_case(&cap.name) && *rate == cap.clock_rate)
        {
            if offered_pts.contains(pt) && !accepted.contains(pt) {
                accepted.push(*pt);
            }
        }
    }

    // Phase 2: telephone-event (RFC 4733) — append if offered and locally supported.
    if caps.support_telephone_event() {
        for (pt, name, _) in rtpmaps {
            if name.eq_ignore_ascii_case("telephone-event")
                && offered_pts.contains(pt)
                && !accepted.contains(pt)
            {
                accepted.push(*pt);
            }
        }
    }

    // Phase 3: static PTs (no rtpmap line) — PCMU=0, PCMA=8, G722=9, etc.
    for &pt in offered_pts {
        if accepted.contains(&pt) {
            continue;
        }
        if rtpmaps.iter().any(|(p, _, _)| *p == pt) {
            continue;
        } // has rtpmap
        if let Some((name, rate)) = static_codec_for_pt(pt) {
            if caps.allows(name, rate) {
                accepted.push(pt);
            }
        }
    }

    accepted
}

fn offer_direction(m: &Media) -> &str {
    m.attributes
        .iter()
        .find(|a| is_direction(&a.attribute))
        .map(|a| a.attribute.as_str())
        .unwrap_or("sendrecv") // RFC 3264 §6.1 default
}

fn flip_direction(dir: &str) -> &str {
    match dir {
        "sendonly" => "recvonly",
        "recvonly" => "sendonly",
        "inactive" => "inactive",
        _ => "sendrecv",
    }
}

fn is_direction(name: &str) -> bool {
    matches!(name, "sendrecv" | "sendonly" | "recvonly" | "inactive")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{CodecCapabilities, RtpCodec};
    use crate::session::parse_sdp;

    fn opus_pcmu_caps() -> CodecCapabilities {
        CodecCapabilities::new(vec![
            RtpCodec::new("opus", 48000).with_channels(2),
            RtpCodec::new("PCMU", 8000),
        ])
    }

    const OFFER_3_CODECS: &str = "\
v=0\r\n\
o=alice 1 1 IN IP4 192.0.2.1\r\n\
s=-\r\n\
t=0 0\r\n\
m=audio 49170 RTP/AVP 111 0 8\r\n\
a=rtpmap:111 opus/48000/2\r\n\
a=fmtp:111 usedtx=1\r\n\
a=sendrecv\r\n";

    const OFFER_SENDONLY: &str = "\
v=0\r\n\
o=alice 1 1 IN IP4 192.0.2.1\r\n\
s=-\r\n\
t=0 0\r\n\
m=audio 49170 RTP/AVP 0\r\n\
a=sendonly\r\n";

    const OFFER_TELEPHONE_EVENT: &str = "\
v=0\r\n\
o=alice 1 1 IN IP4 192.0.2.1\r\n\
s=-\r\n\
t=0 0\r\n\
m=audio 49170 RTP/AVP 111 101\r\n\
a=rtpmap:111 opus/48000/2\r\n\
a=rtpmap:101 telephone-event/8000\r\n\
a=fmtp:101 0-15\r\n\
a=sendrecv\r\n";

    const OFFER_FINGERPRINT: &str = "\
v=0\r\n\
o=alice 1 1 IN IP4 192.0.2.1\r\n\
s=-\r\n\
t=0 0\r\n\
m=audio 49170 UDP/TLS/RTP/SAVPF 111\r\n\
a=rtpmap:111 opus/48000/2\r\n\
a=fingerprint:sha-256 AA:BB:CC\r\n\
a=setup:actpass\r\n\
a=sendrecv\r\n";

    #[test]
    fn offer_3_codecs_answer_intersects_to_2() {
        let offer = parse_sdp(OFFER_3_CODECS).unwrap();
        let caps = opus_pcmu_caps();
        let answer = negotiate_sdp_answer(&offer, &caps, 2).unwrap();
        let m = &answer.medias[0];
        // opus (PT=111) and PCMU (PT=0) both in caps; G711a (PT=8) is not
        let pts: Vec<&str> = m.fmt.split_whitespace().collect();
        assert_eq!(
            pts,
            &["111", "0"],
            "only opus and PCMU accepted, in caps order"
        );
    }

    #[test]
    fn sendonly_offer_gets_recvonly_answer() {
        let offer = parse_sdp(OFFER_SENDONLY).unwrap();
        let caps = CodecCapabilities::new(vec![RtpCodec::new("PCMU", 8000)]);
        let answer = negotiate_sdp_answer(&offer, &caps, 1).unwrap();
        let dir = answer.medias[0]
            .attributes
            .iter()
            .find(|a| is_direction(&a.attribute))
            .map(|a| a.attribute.as_str());
        assert_eq!(dir, Some("recvonly"));
    }

    #[test]
    fn telephone_event_preserved_in_answer() {
        let offer = parse_sdp(OFFER_TELEPHONE_EVENT).unwrap();
        let caps = CodecCapabilities::new(vec![RtpCodec::new("opus", 48000).with_channels(2)]);
        let answer = negotiate_sdp_answer(&offer, &caps, 1).unwrap();
        let m = &answer.medias[0];
        let pts: Vec<&str> = m.fmt.split_whitespace().collect();
        assert!(
            pts.contains(&"101"),
            "telephone-event (PT 101) must be in answer"
        );
        // fmtp:101 0-15 must be preserved
        let has_fmtp = m
            .attributes
            .iter()
            .any(|a| a.attribute == "fmtp" && a.value.as_deref().unwrap_or("").starts_with("101 "));
        assert!(has_fmtp, "fmtp:101 0-15 must be preserved");
    }

    #[test]
    fn fingerprint_unmodified_in_passthrough() {
        let offer = parse_sdp(OFFER_FINGERPRINT).unwrap();
        let caps = CodecCapabilities::new(vec![RtpCodec::new("opus", 48000).with_channels(2)]);
        let answer = negotiate_sdp_answer(&offer, &caps, 1).unwrap();
        let m = &answer.medias[0];
        let fp = m
            .attributes
            .iter()
            .find(|a| a.attribute == "fingerprint")
            .and_then(|a| a.value.as_deref());
        assert_eq!(
            fp,
            Some("sha-256 AA:BB:CC"),
            "fingerprint must pass through unchanged"
        );
    }

    #[test]
    fn no_matching_codecs_rejects_media_section() {
        let offer = parse_sdp(OFFER_SENDONLY).unwrap();
        let caps = CodecCapabilities::new(vec![RtpCodec::new("G729", 8000)]);
        let answer = negotiate_sdp_answer(&offer, &caps, 1).unwrap();
        assert_eq!(answer.medias[0].port, 0, "port=0 when no codecs match");
    }

    #[test]
    fn reinvite_codec_change_updates_version() {
        let offer = parse_sdp(OFFER_3_CODECS).unwrap();
        let caps = opus_pcmu_caps();
        let v1 = negotiate_sdp_answer(&offer, &caps, 1).unwrap();
        let v2 = negotiate_sdp_answer(&offer, &caps, 2).unwrap();
        assert_eq!(v1.origin.sess_version, 1);
        assert_eq!(v2.origin.sess_version, 2);
    }
}
