use crate::encode::Encode;
use crate::session_key_components::Decode;
use crate::ChunkContent;
use cookie_factory::{GenResult, WriteContext};
use nom::IResult;
use std::io::Write;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PingReplyBody {
    pub message_echo: Vec<u8>,
}

impl<T: Write> Encode<T> for PingReplyBody {
    fn encode(&self, w: WriteContext<T>) -> GenResult<T> {
        self.message_echo.encode(w)
    }
}
static_encode!(PingReplyBody);
impl Decode for PingReplyBody {
    fn decode(i: &[u8]) -> IResult<&[u8], Self> {
        Ok((
            &[],
            Self {
                message_echo: i.to_vec(),
            },
        ))
    }
}
impl From<PingReplyBody> for ChunkContent {
    fn from(s: PingReplyBody) -> Self {
        ChunkContent::PingReply(s)
    }
}

#[cfg(test)]
pub mod test {
    use crate::{Decode, PingReplyBody, StaticEncode};

    #[test]
    pub fn pingreply_roundtrip() {
        let packet = PingReplyBody {
            message_echo: vec![1, 2, 3, 4],
        };
        let enc = packet.encode_static();
        let (i, dec) = PingReplyBody::decode(&enc).unwrap();
        assert_eq!(dec, packet);
        assert_eq!(i, &[]);
    }
}
