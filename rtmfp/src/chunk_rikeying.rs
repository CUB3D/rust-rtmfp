use crate::encode::StaticEncode;

use crate::session_key_components::{Decode, SessionKeyingComponent};
use crate::vlu::VLU;
use crate::ChunkContent;
use nom::IResult;
use parse::{GenerateBytes, ParseBytes, SliceWriter, VecSliceWriter};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ResponderInitialKeyingChunkBody {
    pub responder_session_id: u32,
    pub skrc_length: VLU,
    pub session_key_responder_component: SessionKeyingComponent,
    pub signature: Vec<u8>,
}

impl StaticEncode for ResponderInitialKeyingChunkBody {
    //TODO: drop
    fn encode_static(&self) -> Vec<u8> {
        let mut sw = VecSliceWriter::default();
        self.generate(&mut sw);
        sw.as_slice().to_vec()
    }
}

impl GenerateBytes for ResponderInitialKeyingChunkBody {
    fn generate<'b>(&'b self, sw: &'b mut impl SliceWriter) {
        sw.be_u32(self.responder_session_id);
        self.skrc_length.generate(sw);
        self.session_key_responder_component.generate(sw);
        sw.put(self.signature.as_slice());
    }
}

impl Decode for ResponderInitialKeyingChunkBody {
    fn decode(i: &[u8]) -> IResult<&[u8], Self> {
        let (i, responder_session_id) = nom::number::complete::be_u32(i)?;
        let (i, skrc_length) = VLU::decode(i)?;

        let _skrc_bytes = &i[..skrc_length.value as usize];
        //TODO: should this not be skrc_bytes not i
        let (_empty, session_key_responder_component) = SessionKeyingComponent::parse(i)?;
        let signature = i[skrc_length.value as usize..].to_vec();

        Ok((
            &[],
            Self {
                responder_session_id,
                skrc_length,
                session_key_responder_component,
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
    use crate::session_key_components::{Decode, SessionKeyingComponent};
    use parse::{GenerateBytes, SliceWriter, VecSliceWriter};
    use crate::chunk_rikeying::ResponderInitialKeyingChunkBody;

    #[test]
    pub fn rikeying_round_trip() {
        let packet = ResponderInitialKeyingChunkBody {
            responder_session_id: 0,
            skrc_length: 0.into(),
            session_key_responder_component: SessionKeyingComponent::default(),
            signature: Vec::new(),
        };
        let mut sw = VecSliceWriter::default();
        packet.generate(&mut sw);
        let (i, dec) = ResponderInitialKeyingChunkBody::decode(sw.as_slice()).unwrap();
        assert_eq!(dec, packet);
        assert_eq!(i, &[]);
    }
}
