use crate::types::message::SipVersion;
use crate::types::status::StatusCode;
use nom::IResult;
use nom::bytes::complete::take_while;

pub fn parse_status_line(input: &[u8]) -> IResult<&[u8], (SipVersion, StatusCode, String)> {
    let (rest, _) = nom::bytes::complete::tag(&b"SIP/"[..])(input)?;
    let (rest, major) = super::parse_u32(rest)?;
    let (rest, _) = nom::bytes::complete::tag(&b"."[..])(rest)?;
    let (rest, minor) = super::parse_u32(rest)?;
    let (rest, _) = super::sp(rest)?;
    let (rest, code) = super::parse_u32(rest)?;
    let (rest, _) = super::sp(rest)?;
    let (rest, reason) = take_while(|c| c != b'\r' && c != b'\n')(rest)?;
    let (rest, _) = super::crlf(rest)?;

    let version = SipVersion {
        major: major as u8,
        minor: minor as u8,
    };
    let status = StatusCode(code as u16);
    let reason_str = String::from_utf8_lossy(reason).into_owned();
    Ok((rest, (version, status, reason_str)))
}
