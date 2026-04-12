use crate::session_key_components::Decode;
use crate::ChunkContent;
use nom::IResult;
use parse::{GenerateBytes, SliceWriter};

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct SessionCloseRequestBody;

impl GenerateBytes for SessionCloseRequestBody {
    fn generate<'b>(&'b self, _sw: &'b mut impl SliceWriter) {}
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
