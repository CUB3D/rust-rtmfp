#[derive(Debug)]
pub enum RtmfpError {

}

//TODO: drop this
impl From<RtmfpError> for nom::Err<nom::error::Error<&[u8]>> {
    fn from(value: RtmfpError) -> Self {
        Self::Error(nom::error::Error::new(&[], nom::error::ErrorKind::Tag))
    }
}