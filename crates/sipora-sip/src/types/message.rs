use crate::types::header::{CSeq, ContactValue, Header, NameAddr, Via};
use crate::types::method::Method;
use crate::types::status::StatusCode;

#[derive(Debug, Clone)]
pub enum SipMessage {
    Request(Request),
    Response(Response),
}

#[derive(Debug, Clone)]
pub struct Request {
    pub method: Method,
    pub uri: String,
    pub version: SipVersion,
    pub headers: Vec<Header>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Response {
    pub version: SipVersion,
    pub status: StatusCode,
    pub reason: String,
    pub headers: Vec<Header>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SipVersion {
    pub major: u8,
    pub minor: u8,
}

impl SipVersion {
    pub const V2_0: Self = Self { major: 2, minor: 0 };
}

impl std::fmt::Display for SipVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SIP/{}.{}", self.major, self.minor)
    }
}

impl Request {
    pub fn call_id(&self) -> Option<&str> {
        self.headers.iter().find_map(|h| match h {
            Header::CallId(id) => Some(id.as_str()),
            _ => None,
        })
    }

    pub fn cseq(&self) -> Option<&CSeq> {
        self.headers.iter().find_map(|h| match h {
            Header::CSeq(cs) => Some(cs),
            _ => None,
        })
    }

    pub fn max_forwards(&self) -> Option<u8> {
        self.headers.iter().find_map(|h| match h {
            Header::MaxForwards(mf) => Some(*mf),
            _ => None,
        })
    }

    pub fn via(&self) -> Vec<&Via> {
        self.headers
            .iter()
            .filter_map(|h| match h {
                Header::Via(v) => Some(v),
                _ => None,
            })
            .collect()
    }

    pub fn from_header(&self) -> Option<&NameAddr> {
        self.headers.iter().find_map(|h| match h {
            Header::From(na) => Some(na),
            _ => None,
        })
    }

    pub fn to_header(&self) -> Option<&NameAddr> {
        self.headers.iter().find_map(|h| match h {
            Header::To(na) => Some(na),
            _ => None,
        })
    }

    pub fn contacts(&self) -> Vec<&ContactValue> {
        self.headers
            .iter()
            .flat_map(|h| match h {
                Header::Contact(cs) => cs.iter().collect::<Vec<_>>(),
                _ => vec![],
            })
            .collect()
    }

    pub fn expires(&self) -> Option<u32> {
        self.headers.iter().find_map(|h| match h {
            Header::Expires(e) => Some(*e),
            _ => None,
        })
    }
}

impl Response {
    pub fn call_id(&self) -> Option<&str> {
        self.headers.iter().find_map(|h| match h {
            Header::CallId(id) => Some(id.as_str()),
            _ => None,
        })
    }

    pub fn cseq(&self) -> Option<&CSeq> {
        self.headers.iter().find_map(|h| match h {
            Header::CSeq(cs) => Some(cs),
            _ => None,
        })
    }

    pub fn contacts(&self) -> Vec<&ContactValue> {
        self.headers
            .iter()
            .flat_map(|h| match h {
                Header::Contact(cs) => cs.iter().collect::<Vec<_>>(),
                _ => vec![],
            })
            .collect()
    }
}
