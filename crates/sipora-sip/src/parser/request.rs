use crate::types::message::SipVersion;
use crate::types::method::Method;
use nom::IResult;

pub fn parse_request_line(input: &[u8]) -> IResult<&[u8], (Method, String, SipVersion)> {
    let (rest, method_bytes) = super::token(input)?;
    let (rest, _) = super::sp(rest)?;
    let (rest, uri_bytes) = super::uri::sip_uri(rest)?;
    let (rest, _) = super::sp(rest)?;
    let (rest, version) = parse_sip_version(rest)?;
    let (rest, _) = super::crlf(rest)?;

    let method = Method::from_bytes(method_bytes);
    let uri = String::from_utf8_lossy(uri_bytes).into_owned();
    Ok((rest, (method, uri, version)))
}

fn parse_sip_version(input: &[u8]) -> IResult<&[u8], SipVersion> {
    let (rest, _) = nom::bytes::complete::tag(&b"SIP/"[..])(input)?;
    let (rest, major) = super::parse_u32(rest)?;
    let (rest, _) = nom::bytes::complete::tag(&b"."[..])(rest)?;
    let (rest, minor) = super::parse_u32(rest)?;
    Ok((
        rest,
        SipVersion {
            major: major as u8,
            minor: minor as u8,
        },
    ))
}
