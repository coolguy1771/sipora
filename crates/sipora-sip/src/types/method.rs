use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Method {
    Invite,
    Ack,
    Bye,
    Cancel,
    Register,
    Options,
    Info,
    Prack,
    Subscribe,
    Notify,
    Publish,
    Refer,
    Message,
    Update,
    Other(String),
}

impl Method {
    pub fn from_bytes(input: &[u8]) -> Self {
        match input {
            b"INVITE" => Self::Invite,
            b"ACK" => Self::Ack,
            b"BYE" => Self::Bye,
            b"CANCEL" => Self::Cancel,
            b"REGISTER" => Self::Register,
            b"OPTIONS" => Self::Options,
            b"INFO" => Self::Info,
            b"PRACK" => Self::Prack,
            b"SUBSCRIBE" => Self::Subscribe,
            b"NOTIFY" => Self::Notify,
            b"PUBLISH" => Self::Publish,
            b"REFER" => Self::Refer,
            b"MESSAGE" => Self::Message,
            b"UPDATE" => Self::Update,
            other => Self::Other(String::from_utf8_lossy(other).into_owned()),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Invite => "INVITE",
            Self::Ack => "ACK",
            Self::Bye => "BYE",
            Self::Cancel => "CANCEL",
            Self::Register => "REGISTER",
            Self::Options => "OPTIONS",
            Self::Info => "INFO",
            Self::Prack => "PRACK",
            Self::Subscribe => "SUBSCRIBE",
            Self::Notify => "NOTIFY",
            Self::Publish => "PUBLISH",
            Self::Refer => "REFER",
            Self::Message => "MESSAGE",
            Self::Update => "UPDATE",
            Self::Other(s) => s.as_str(),
        }
    }
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
