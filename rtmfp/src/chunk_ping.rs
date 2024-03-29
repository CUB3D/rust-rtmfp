use crate::encode::Encode;
use crate::session_key_components::Decode;
use crate::ChunkContent;
use cookie_factory::{GenResult, WriteContext};
use nom::IResult;
use std::io::Write;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PingBody {
    pub message: Vec<u8>,
}

impl<T: Write> Encode<T> for PingBody {
    fn encode(&self, w: WriteContext<T>) -> GenResult<T> {
        self.message.encode(w)
    }
}
static_encode!(PingBody);
impl Decode for PingBody {
    fn decode(i: &[u8]) -> IResult<&[u8], Self> {
        Ok((
            &[],
            Self {
                message: i.to_vec(),
            },
        ))
    }
}
impl From<PingBody> for ChunkContent {
    fn from(s: PingBody) -> Self {
        ChunkContent::Ping(s)
    }
}

#[cfg(test)]
pub mod test {
    use crate::{Decode, PingBody, StaticEncode};

    #[test]
    pub fn ping_roundtrip() {
        let packet = PingBody {
            message: vec![1, 2, 3, 4],
        };
        let enc = packet.encode_static();
        let (i, dec) = PingBody::decode(&enc).unwrap();
        assert_eq!(dec, packet);
        assert_eq!(i, &[]);
    }
}
