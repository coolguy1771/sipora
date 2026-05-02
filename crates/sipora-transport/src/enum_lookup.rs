//! DNS ENUM (`e164.arpa` NAPTR) resolution for `tel:` URIs.

use hickory_resolver::proto::rr::{RData, RecordType};
use regex::Regex;

use crate::dns::dns_lookup;

fn e164_arpa_domain(digits: &str) -> String {
    let mut s = String::new();
    for (i, ch) in digits.chars().rev().enumerate() {
        if i > 0 {
            s.push('.');
        }
        s.push(ch);
    }
    s.push_str(".e164.arpa");
    s
}

/// RFC 3402 `Delimiter ERE Delimiter Replacement Delimiter Flags` (ASCII).
fn naptr_regexp_fields(regexp: &str) -> Option<(String, String, String)> {
    let b = regexp.as_bytes();
    if b.is_empty() {
        return None;
    }
    let delim = b[0];
    let mut fields: Vec<String> = Vec::new();
    let mut cur: Vec<u8> = Vec::new();
    let mut i = 1usize;
    while i < b.len() {
        if b[i] == delim {
            let mut bs = 0usize;
            let mut j = i;
            while j > 0 && b[j - 1] == b'\\' {
                bs += 1;
                j -= 1;
            }
            if bs.is_multiple_of(2) {
                fields.push(String::from_utf8_lossy(&cur).into_owned());
                cur.clear();
                i += 1;
                continue;
            }
        }
        cur.push(b[i]);
        i += 1;
    }
    fields.push(String::from_utf8_lossy(&cur).into_owned());
    if fields.len() < 3 {
        return None;
    }
    Some((fields[0].clone(), fields[1].clone(), fields[2].clone()))
}

fn apply_naptr_replacement(repl: &str, caps: &regex::Captures<'_>) -> String {
    let mut out = String::with_capacity(repl.len());
    let mut it = repl.chars().peekable();
    while let Some(ch) = it.next() {
        if (ch == '\\' || ch == '$') && matches!(it.peek(), Some('0'..='9')) {
            let d = it.next().unwrap().to_digit(10).unwrap_or(0) as usize;
            if let Some(m) = caps.get(d) {
                out.push_str(m.as_str());
            }
        } else if ch == '\\' && it.peek() == Some(&'\\') {
            it.next();
            out.push('\\');
        } else {
            out.push(ch);
        }
    }
    out
}

fn is_sip_uri_candidate(s: &str) -> bool {
    let lower = s.trim().to_ascii_lowercase();
    lower.starts_with("sip:") || lower.starts_with("sips:")
}

fn sip_uri_from_naptr_regexp(regexp: &str, digits: &str) -> Option<String> {
    let (pattern, replacement, _flags) = naptr_regexp_fields(regexp)?;
    if pattern == "^.*$" {
        let re = Regex::new("^.*$").ok()?;
        let caps = re.captures(digits)?;
        let out = apply_naptr_replacement(&replacement, &caps);
        return is_sip_uri_candidate(&out).then_some(out);
    }
    let re = Regex::new(&pattern).ok()?;
    let caps = re.captures(digits)?;
    let out = apply_naptr_replacement(&replacement, &caps);
    is_sip_uri_candidate(&out).then_some(out)
}

fn naptr_prefers_sip(services: &str) -> bool {
    let s = services.to_ascii_lowercase();
    s.contains("e2u+sip") || s.contains("sip+e2u")
}

fn sip_service_rank(services: &str) -> u8 {
    let s = services.to_ascii_lowercase();
    if s.contains("sip+e2u") {
        0
    } else if s.contains("e2u+sip") {
        1
    } else {
        2
    }
}

/// Resolve E.164 digits (no `+`) to a SIP or SIPS URI via ENUM NAPTR.
pub async fn enum_resolve_tel_to_sip(digits: &str) -> Option<String> {
    if digits.is_empty() {
        return None;
    }
    let domain = e164_arpa_domain(digits);
    let lookup = dns_lookup(&domain, RecordType::NAPTR).await?;
    let mut naptrs: Vec<(u16, u16, u8, String)> = Vec::new();

    for record in lookup.answers() {
        let RData::NAPTR(naptr) = &record.data else {
            continue;
        };
        let services = String::from_utf8_lossy(&naptr.services);
        if !naptr_prefers_sip(&services) {
            continue;
        }
        let regexp = String::from_utf8_lossy(&naptr.regexp);
        let rank = sip_service_rank(&services);
        if let Some(uri) = sip_uri_from_naptr_regexp(&regexp, digits) {
            naptrs.push((naptr.order, naptr.preference, rank, uri));
        }
    }

    naptrs.sort_by_key(|a| (a.0, a.1, a.2));
    naptrs.into_iter().next().map(|(_, _, _, uri)| uri)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_e164_arpa_domain() {
        assert_eq!(e164_arpa_domain("44123"), "3.2.1.4.4.e164.arpa".to_string());
    }

    #[test]
    fn parses_classic_enum_regexp() {
        let u = sip_uri_from_naptr_regexp("!^.*$!sip:user@example.com!", "14155550100");
        assert_eq!(u.as_deref(), Some("sip:user@example.com"));
    }

    #[test]
    fn naptr_regexp_substitutes_capture_groups() {
        let u = sip_uri_from_naptr_regexp("!^\\+?(.*)$!sip:$1@example.com!", "14155550100");
        assert_eq!(u.as_deref(), Some("sip:14155550100@example.com"));
    }
}
