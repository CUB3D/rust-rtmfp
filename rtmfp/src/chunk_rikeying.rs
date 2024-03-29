use crate::encode::Encode;

use crate::session_key_components::{Decode, SessionKeyingComponent};
use crate::vlu::VLU;
use crate::ChunkContent;
use cookie_factory::bytes::be_u32;
use cookie_factory::sequence::tuple;
use cookie_factory::{GenResult, WriteContext};
use nom::IResult;
use std::io::Write;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ResponderInitialKeyingChunkBody {
    pub responder_session_id: u32,
    pub skrc_length: VLU,
    pub session_key_responder_component: SessionKeyingComponent,
    pub signature: Vec<u8>,
}

impl<T: Write> Encode<T> for ResponderInitialKeyingChunkBody {
    fn encode(&self, w: WriteContext<T>) -> GenResult<T> {
        tuple((
            be_u32(self.responder_session_id),
            self.skrc_length.encode(),
            move |out| self.session_key_responder_component.encode(out),
            move |out| self.signature.encode(out),
        ))(w)
    }
}
static_encode!(ResponderInitialKeyingChunkBody);

impl Decode for ResponderInitialKeyingChunkBody {
    fn decode(i: &[u8]) -> IResult<&[u8], Self> {
        let (i, responder_session_id) = nom::number::complete::be_u32(i)?;
        let (i, skrc_length) = VLU::decode(i)?;

        let _skrc_bytes = &i[..skrc_length.value as usize];
        //TODO: should this not be skrc_bytes not i
        let (_empty, session_key_responder_component) = SessionKeyingComponent::decode(i)?;
        let signature = i[skrc_length.value as usize..].to_vec();

        Ok((
            &[],
            Self {
                responder_session_id,
                skrc_length,
                session_key_responder_component: session_key_responder_component.to_vec(),
                signature,
            },
        ))
    }
}
impl From<ResponderInitialKeyingChunkBody> for ChunkContent {
    fn from(s: ResponderInitialKeyingChunkBody) -> Self {
        ChunkContent::RIKeying(s)
    }
}

#[cfg(test)]
pub mod test {
    use crate::endpoint_discriminator::AncillaryDataBody;
    use crate::flash_certificate::FlashCertificate;
    use crate::session_key_components::SessionKeyingComponent;
    use crate::{Decode, ResponderInitialKeyingChunkBody, StaticEncode};

    #[test]
    pub fn rikeying_roundtrip() {
        let packet = ResponderInitialKeyingChunkBody {
            responder_session_id: 0,
            skrc_length: 0.into(),
            session_key_responder_component: vec![],
            signature: vec![],
        };
        let enc = packet.encode_static();
        let (i, dec) = ResponderInitialKeyingChunkBody::decode(&enc).unwrap();
        assert_eq!(dec, packet);
        assert_eq!(i, &[]);
    }
}
