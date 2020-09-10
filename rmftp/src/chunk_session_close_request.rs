use crate::encode::Encode;
use crate::session_key_components::Decode;
use crate::ChunkContent;
use cookie_factory::{GenResult, WriteContext};
use nom::IResult;
use std::io::Write;

#[derive(Debug, Clone, Default)]
pub struct SessionCloseRequestBody;

impl<T: Write> Encode<T> for SessionCloseRequestBody {
    fn encode(&self, w: WriteContext<T>) -> GenResult<T> {
        Ok(w)
    }
}
impl Decode for SessionCloseRequestBody {
    fn decode(i: &[u8]) -> IResult<&[u8], Self> {
        Ok((i, Self::default()))
    }
}
impl From<SessionCloseRequestBody> for ChunkContent {
    fn from(s: SessionCloseRequestBody) -> Self {
        ChunkContent::SessionCloseRequest(s)
    }
}
