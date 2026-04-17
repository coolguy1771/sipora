use nom::IResult;
use nom::bytes::complete::{tag, take_while1};

fn is_uri_char(c: u8) -> bool {
    c.is_ascii_graphic() && c != b'>' && c != b' '
}

pub fn sip_uri(input: &[u8]) -> IResult<&[u8], &[u8]> {
    take_while1(is_uri_char)(input)
}

pub fn angle_bracket_uri(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let (rest, _) = tag(&b"<"[..])(input)?;
    let (rest, uri) = take_while1(|c| c != b'>')(rest)?;
    let (rest, _) = tag(&b">"[..])(rest)?;
    Ok((rest, uri))
}

pub fn uri_or_angle(input: &[u8]) -> IResult<&[u8], &[u8]> {
    if input.first() == Some(&b'<') {
        angle_bracket_uri(input)
    } else {
        sip_uri(input)
    }
}
