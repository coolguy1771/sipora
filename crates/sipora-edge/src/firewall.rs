use sipora_sip::types::header::Header;
use sipora_sip::types::message::Request;

#[derive(Clone)]
pub struct SipFirewall {
    pub strip_topology: bool,
    pub strict_syntax: bool,
    options_rate: u32,
}

impl SipFirewall {
    pub fn new(strip_topology: bool, strict_syntax: bool, options_rate: u32) -> Self {
        Self {
            strip_topology,
            strict_syntax,
            options_rate,
        }
    }

    pub fn strip_topology_headers(&self, headers: &[Header]) -> Vec<Header> {
        if !self.strip_topology {
            return headers.to_vec();
        }
        headers
            .iter()
            .filter_map(|h| match h {
                Header::Via(via) => {
                    if is_internal_address(&via.host) {
                        None
                    } else {
                        Some(h.clone())
                    }
                }
                Header::RecordRoute(routes) => {
                    let filtered: Vec<String> = routes
                        .iter()
                        .filter(|r| !contains_internal_address(r))
                        .cloned()
                        .collect();
                    if filtered.is_empty() {
                        None
                    } else {
                        Some(Header::RecordRoute(filtered))
                    }
                }
                _ => Some(h.clone()),
            })
            .collect()
    }

    pub fn validate_required_headers(&self, req: &Request) -> std::result::Result<(), String> {
        if !self.strict_syntax {
            return Ok(());
        }
        if req.call_id().is_none() {
            return Err("missing Call-ID header".into());
        }
        if req.cseq().is_none() {
            return Err("missing CSeq header".into());
        }
        if req.from_header().is_none() {
            return Err("missing From header".into());
        }
        if req.to_header().is_none() {
            return Err("missing To header".into());
        }
        if req.via().is_empty() {
            return Err("missing Via header".into());
        }
        Ok(())
    }

    /// Strips CR, LF, and null bytes to prevent SIP header injection.
    pub fn sanitize_display_name(name: &str) -> String {
        name.chars()
            .filter(|c| *c != '\r' && *c != '\n' && *c != '\0')
            .collect()
    }

    pub fn options_rate_limit(&self) -> u32 {
        self.options_rate
    }
}

fn is_internal_address(host: &str) -> bool {
    use std::net::{IpAddr, Ipv6Addr};

    let Ok(ip) = host.parse::<IpAddr>() else {
        return false;
    };
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unique_local() || v6 == Ipv6Addr::UNSPECIFIED,
    }
}

fn contains_internal_address(route: &str) -> bool {
    if let Some(start) = route.find("sip:") {
        let rest = &route[start + 4..];
        let host = rest.split(&[':', ';', '>'][..]).next().unwrap_or("");
        return is_internal_address(host);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_internal_address() {
        assert!(is_internal_address("10.0.1.5"));
        assert!(is_internal_address("192.168.1.1"));
        assert!(is_internal_address("172.16.0.1"));
        assert!(is_internal_address("172.31.255.255"));
        assert!(!is_internal_address("172.200.0.1"));
        assert!(!is_internal_address("203.0.113.1"));
        assert!(!is_internal_address("sip.example.com"));
    }

    #[test]
    fn test_sanitize_display_name() {
        assert_eq!(
            SipFirewall::sanitize_display_name("Alice\r\nEvil: header"),
            "AliceEvil: header"
        );
    }
}
