use crate::types::header::*;
use crate::types::message::*;

pub fn serialize_message(msg: &SipMessage) -> Vec<u8> {
    match msg {
        SipMessage::Request(req) => serialize_request(req),
        SipMessage::Response(resp) => serialize_response(resp),
    }
}

pub fn serialize_request(req: &Request) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1024);
    buf.extend_from_slice(req.method.as_str().as_bytes());
    buf.push(b' ');
    buf.extend_from_slice(req.uri.as_bytes());
    buf.extend_from_slice(b" SIP/");
    buf.extend_from_slice(req.version.major.to_string().as_bytes());
    buf.push(b'.');
    buf.extend_from_slice(req.version.minor.to_string().as_bytes());
    buf.extend_from_slice(b"\r\n");
    serialize_headers(&req.headers, &mut buf);
    buf.extend_from_slice(b"\r\n");
    buf.extend_from_slice(&req.body);
    buf
}

pub fn serialize_response(resp: &Response) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1024);
    buf.extend_from_slice(b"SIP/");
    buf.extend_from_slice(resp.version.major.to_string().as_bytes());
    buf.push(b'.');
    buf.extend_from_slice(resp.version.minor.to_string().as_bytes());
    buf.push(b' ');
    buf.extend_from_slice(resp.status.0.to_string().as_bytes());
    buf.push(b' ');
    buf.extend_from_slice(resp.reason.as_bytes());
    buf.extend_from_slice(b"\r\n");
    serialize_headers(&resp.headers, &mut buf);
    buf.extend_from_slice(b"\r\n");
    buf.extend_from_slice(&resp.body);
    buf
}

fn serialize_headers(headers: &[Header], buf: &mut Vec<u8>) {
    for header in headers {
        buf.extend_from_slice(header.name().as_bytes());
        buf.extend_from_slice(b": ");
        serialize_header_value(header, buf);
        buf.extend_from_slice(b"\r\n");
    }
}

fn serialize_header_value(header: &Header, buf: &mut Vec<u8>) {
    match header {
        Header::Via(via) => serialize_via(via, buf),
        Header::From(na) | Header::To(na) => serialize_name_addr(na, buf),
        Header::CallId(id) => buf.extend_from_slice(id.as_bytes()),
        Header::CSeq(cs) => {
            buf.extend_from_slice(cs.seq.to_string().as_bytes());
            buf.push(b' ');
            buf.extend_from_slice(cs.method.as_str().as_bytes());
        }
        Header::Contact(contacts) => serialize_contacts(contacts, buf),
        Header::MaxForwards(mf) => {
            buf.extend_from_slice(mf.to_string().as_bytes());
        }
        Header::ContentLength(n) => {
            buf.extend_from_slice(n.to_string().as_bytes());
        }
        Header::ContentType(ct) => buf.extend_from_slice(ct.as_bytes()),
        Header::Route(routes) | Header::RecordRoute(routes) => {
            buf.extend_from_slice(routes.join(", ").as_bytes());
        }
        Header::Expires(e) | Header::MinExpires(e) | Header::RetryAfter(e) => {
            buf.extend_from_slice(e.to_string().as_bytes());
        }
        Header::Authorization(v)
        | Header::WwwAuthenticate(v)
        | Header::ProxyAuthenticate(v)
        | Header::ProxyAuthorization(v)
        | Header::UserAgent(v) => buf.extend_from_slice(v.as_bytes()),
        Header::Allow(methods) => {
            let s: Vec<&str> = methods.iter().map(|m| m.as_str()).collect();
            buf.extend_from_slice(s.join(", ").as_bytes());
        }
        Header::Supported(vals) | Header::Require(vals) => {
            buf.extend_from_slice(vals.join(", ").as_bytes());
        }
        Header::Extension { value, .. } => {
            buf.extend_from_slice(value.as_bytes());
        }
    }
}

fn serialize_via(via: &Via, buf: &mut Vec<u8>) {
    buf.extend_from_slice(b"SIP/2.0/");
    buf.extend_from_slice(via.transport.as_str().as_bytes());
    buf.push(b' ');
    buf.extend_from_slice(via.host.as_bytes());
    if let Some(port) = via.port {
        buf.push(b':');
        buf.extend_from_slice(port.to_string().as_bytes());
    }
    if !via.branch.is_empty() {
        buf.extend_from_slice(b";branch=");
        buf.extend_from_slice(via.branch.as_bytes());
    }
    if let Some(recv) = &via.received {
        buf.extend_from_slice(b";received=");
        buf.extend_from_slice(recv.as_bytes());
    }
    if let Some(rp) = via.rport {
        buf.extend_from_slice(b";rport=");
        buf.extend_from_slice(rp.to_string().as_bytes());
    }
}

fn serialize_name_addr(na: &NameAddr, buf: &mut Vec<u8>) {
    if let Some(dn) = &na.display_name {
        buf.extend_from_slice(b"\"");
        buf.extend_from_slice(dn.as_bytes());
        buf.extend_from_slice(b"\" ");
    }
    buf.extend_from_slice(b"<");
    buf.extend_from_slice(na.uri.as_bytes());
    buf.extend_from_slice(b">");
    if let Some(tag) = &na.tag {
        buf.extend_from_slice(b";tag=");
        buf.extend_from_slice(tag.as_bytes());
    }
}

fn serialize_contacts(contacts: &[ContactValue], buf: &mut Vec<u8>) {
    for (i, c) in contacts.iter().enumerate() {
        if i > 0 {
            buf.extend_from_slice(b", ");
        }
        if c.uri == "*" {
            buf.push(b'*');
        } else {
            buf.extend_from_slice(b"<");
            buf.extend_from_slice(c.uri.as_bytes());
            buf.extend_from_slice(b">");
        }
        if let Some(q) = c.q {
            buf.extend_from_slice(format!(";q={q:.1}").as_bytes());
        }
        if let Some(e) = c.expires {
            buf.extend_from_slice(format!(";expires={e}").as_bytes());
        }
    }
}
