use sdp_types::Session;

pub fn parse_sdp(input: &str) -> crate::Result<Session> {
    Session::parse(input.as_bytes()).map_err(|e| crate::SdpError::Parse(format!("{e:?}")))
}
