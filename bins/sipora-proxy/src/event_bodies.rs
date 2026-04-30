//! XML bodies for NOTIFY (reginfo, PIDF pass-through).

use sipora_location::ContactBinding;

fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(ch),
        }
    }
    out
}

/// RFC 3680 `application/reginfo+xml` for `reg` event package.
pub fn reginfo_xml(aor: &str, bindings: &[ContactBinding], version: u32) -> String {
    let aor_e = xml_escape(aor);
    let mut contacts = String::new();
    for (i, b) in bindings.iter().enumerate() {
        let uri_e = xml_escape(&b.uri);
        contacts.push_str(&format!(
            "<contact id=\"c{i}\"><uri>{uri_e}</uri></contact>\n",
        ));
    }
    format!(
        "<?xml version=\"1.0\"?>\n\
         <reginfo xmlns=\"urn:ietf:params:xml:ns:reginfo\" \
         version=\"{version}\" state=\"full\">\n\
         <registration aor=\"{aor_e}\" id=\"reg1\" state=\"active\">\n\
         {contacts}\
         </registration>\n\
         </reginfo>\n"
    )
}

/// PIDF from stored presence document (already `application/pidf+xml`).
pub fn presence_body_from_doc(body: &[u8]) -> Vec<u8> {
    body.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reginfo_contains_aor_and_uri() {
        let b = ContactBinding {
            uri: "sip:u@10.0.0.1".into(),
            ..Default::default()
        };
        let x = reginfo_xml("sip:user@example.com", &[b], 1);
        assert!(x.contains("sip:user@example.com"));
        assert!(x.contains("sip:u@10.0.0.1"));
        assert!(x.contains("version=\"1\""));
    }

    #[test]
    fn xml_escape_amp() {
        let b = ContactBinding {
            uri: "sip:a&b@h".into(),
            ..Default::default()
        };
        let x = reginfo_xml("sip:x@y", &[b], 0);
        assert!(x.contains("&amp;"));
    }
}
