pub mod headers;
pub mod message;
pub mod request;
pub mod response;
pub mod uri;

use nom::IResult;
use nom::bytes::complete::{tag, take_while1};
use nom::character::complete::{digit1, space1};

pub fn is_token_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || b"-.!%*_+`'~".contains(&c)
}

pub fn token(input: &[u8]) -> IResult<&[u8], &[u8]> {
    take_while1(is_token_char)(input)
}

pub fn crlf(input: &[u8]) -> IResult<&[u8], &[u8]> {
    tag(&b"\r\n"[..])(input)
}

pub fn sp(input: &[u8]) -> IResult<&[u8], &[u8]> {
    space1(input)
}

pub fn parse_u32(input: &[u8]) -> IResult<&[u8], u32> {
    let (rest, digits) = digit1(input)?;
    let s = std::str::from_utf8(digits).unwrap_or("0");
    let n = s.parse::<u32>().unwrap_or(0);
    Ok((rest, n))
}
