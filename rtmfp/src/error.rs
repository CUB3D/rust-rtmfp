use parse::ParseError;

#[derive(Debug)]
pub enum RtmfpError {
    ParseError(ParseError)
}

//TODO: drop this
impl From<RtmfpError> for nom::Err<nom::error::Error<&[u8]>> {
    fn from(_value: RtmfpError) -> Self {
        Self::Error(nom::error::Error::new(&[], nom::error::ErrorKind::Tag))
    }
}

impl From<ParseError> for RtmfpError {
    fn from(p: ParseError) -> Self {
        Self::ParseError(p)
    }
}