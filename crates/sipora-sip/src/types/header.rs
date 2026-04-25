use crate::types::method::Method;

#[derive(Debug, Clone, PartialEq)]
pub enum Header {
    Via(Via),
    From(NameAddr),
    To(NameAddr),
    CallId(String),
    CSeq(CSeq),
    Contact(Vec<ContactValue>),
    MaxForwards(u8),
    ContentLength(u32),
    ContentType(String),
    Route(Vec<String>),
    RecordRoute(Vec<String>),
    Authorization(String),
    WwwAuthenticate(String),
    ProxyAuthenticate(String),
    ProxyAuthorization(String),
    Expires(u32),
    MinExpires(u32),
    UserAgent(String),
    Allow(Vec<Method>),
    Supported(Vec<String>),
    Require(Vec<String>),
    RetryAfter(u32),
    RSeq(u32),
    RAck { rseq: u32, cseq: u32, method: Method },
    SessionExpires { delta_seconds: u32, refresher: Option<Refresher> },
    MinSE(u32),
    Extension { name: String, value: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refresher {
    Uac,
    Uas,
}

impl Refresher {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Uac => "uac",
            Self::Uas => "uas",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Via {
    pub transport: Transport,
    pub host: String,
    pub port: Option<u16>,
    pub branch: String,
    pub received: Option<String>,
    pub rport: RportParam,
    pub params: Vec<(String, Option<String>)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RportParam {
    Absent,
    Requested,
    Filled(u16),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Transport {
    Udp,
    Tcp,
    Tls,
    Ws,
    Wss,
    Other(String),
}

impl Transport {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Udp => "UDP",
            Self::Tcp => "TCP",
            Self::Tls => "TLS",
            Self::Ws => "WS",
            Self::Wss => "WSS",
            Self::Other(s) => s.as_str(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct NameAddr {
    pub display_name: Option<String>,
    pub uri: String,
    pub tag: Option<String>,
    pub params: Vec<(String, Option<String>)>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CSeq {
    pub seq: u32,
    pub method: Method,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ContactValue {
    pub uri: String,
    pub q: Option<f32>,
    pub expires: Option<u32>,
    pub params: Vec<(String, Option<String>)>,
}

impl ContactValue {
    pub fn q_value(&self) -> f32 {
        self.q.unwrap_or(1.0)
    }
}

impl Header {
    pub fn name(&self) -> &str {
        match self {
            Self::Via(_) => "Via",
            Self::From(_) => "From",
            Self::To(_) => "To",
            Self::CallId(_) => "Call-ID",
            Self::CSeq(_) => "CSeq",
            Self::Contact(_) => "Contact",
            Self::MaxForwards(_) => "Max-Forwards",
            Self::ContentLength(_) => "Content-Length",
            Self::ContentType(_) => "Content-Type",
            Self::Route(_) => "Route",
            Self::RecordRoute(_) => "Record-Route",
            Self::Authorization(_) => "Authorization",
            Self::WwwAuthenticate(_) => "WWW-Authenticate",
            Self::ProxyAuthenticate(_) => "Proxy-Authenticate",
            Self::ProxyAuthorization(_) => "Proxy-Authorization",
            Self::Expires(_) => "Expires",
            Self::MinExpires(_) => "Min-Expires",
            Self::UserAgent(_) => "User-Agent",
            Self::Allow(_) => "Allow",
            Self::Supported(_) => "Supported",
            Self::Require(_) => "Require",
            Self::RetryAfter(_) => "Retry-After",
            Self::RSeq(_) => "RSeq",
            Self::RAck { .. } => "RAck",
            Self::SessionExpires { .. } => "Session-Expires",
            Self::MinSE(_) => "Min-SE",
            Self::Extension { name, .. } => name.as_str(),
        }
    }
}
