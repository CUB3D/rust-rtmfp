
use crate::flash_certificate::FlashCertificate;
use crate::session_key_components::{Decode, SessionKeyingComponent};
use crate::vlu::VLU;
use crate::ChunkContent;
use crate::StaticEncode;
use nom::IResult;
use parse::{GenerateBytes, ParseBytes, SliceWriter, VecSliceWriter};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct IIKeyingChunkBody {
    pub initiator_session_id: u32,
    pub cookie_length: VLU,
    pub cookie_echo: Vec<u8>,
    pub cert_length: VLU,
    pub initiator_certificate: FlashCertificate,
    pub skic_length: VLU,
    pub session_key_initiator_component: SessionKeyingComponent,
    pub signature: Vec<u8>,
    pub nonce: Vec<u8>,
}

impl IIKeyingChunkBody {
    pub fn new(
        session_id: u32,
        cookie: Vec<u8>,
        certificate: FlashCertificate,
        skic: SessionKeyingComponent,
    ) -> Self {
        let mut sw2 = VecSliceWriter::default();
        certificate.generate(&mut sw2);
        let cert_size = sw2.as_slice().len();
        let skic_length = skic.encode_static().len();

        Self {
            initiator_session_id: session_id,
            cookie_length: cookie.len().into(),
            cookie_echo: cookie,
            cert_length: cert_size.into(),
            initiator_certificate: certificate,
            skic_length: skic_length.into(),
            session_key_initiator_component: skic,
            signature: Vec::new(),
            nonce: Vec::new(),
        }
    }
}

impl StaticEncode for IIKeyingChunkBody {
    //TODO: drop
    fn encode_static(&self) -> Vec<u8> {
        let mut sw = VecSliceWriter::default();
        self.generate(&mut sw);
        sw.as_slice().to_vec()
    }
}

impl GenerateBytes for IIKeyingChunkBody {
    fn generate<'b>(&'b self, sw: &'b mut impl SliceWriter) {
        println!("SKIC_LEN = {:X}", self.skic_length.value);

        sw.be_u32(self.initiator_session_id);
        self.cookie_length.generate(sw);
        sw.put(self.cookie_echo.as_slice());
        self.cert_length.generate(sw);
        //TODO: compute above length
        self.initiator_certificate.generate(sw);
        // self.skic_length.encode(),
        VLU::from(self.signature.len() + 2).generate(sw);
        //TODO: this is because our key is too long, but we should be using 2 bytes here
        // Assuming this is another bug in VLU encoding?
        sw.ne_u8(0);
        sw.ne_u8(0);


        // move |out| self.session_key_initiator_component.encode(out),
        sw.put(self.signature.as_slice());

        VLU::from(self.nonce.len()).generate(sw);
        sw.put(self.nonce.as_slice());
    }
}

impl Decode for IIKeyingChunkBody {
    fn decode(i: &[u8]) -> IResult<&[u8], Self> {
        let (i, initiator_session_id) = nom::number::complete::be_u32(i)?;
        let (i, cookie_length) = VLU::parse(i)?;
        let cookie = &i[..cookie_length.value as usize];

        let i = &i[cookie_length.value as usize..];
        let (i, cert_length) = VLU::parse(i)?;
        let cert_data = &i[..cert_length.value as usize];
        let (_cert_rem, initiator_certificate) = FlashCertificate::parse(cert_data)?;

        let i = &i[cert_length.value as usize..];
        let (i, skic_length) = VLU::parse(i)?;
        let skic_data = &i[..skic_length.value as usize];
        let (_skik_rem, session_key_initiator_component) =
            SessionKeyingComponent::parse(skic_data)?;

        let signature = &i[skic_length.value as usize..];

        Ok((
            &[],
            Self {
                initiator_session_id,
                cookie_length,
                cookie_echo: cookie.to_vec(),
                cert_length,
                initiator_certificate,
                skic_length,
                session_key_initiator_component,
                signature: signature.to_vec(),
                nonce: Vec::new(),
            },
        ))
    }
}

impl From<IIKeyingChunkBody> for ChunkContent {
    fn from(s: IIKeyingChunkBody) -> Self {
        ChunkContent::IIKeying(s)
    }
}

#[cfg(test)]
pub mod test {
    use crate::flash_certificate::FlashCertificate;
    use crate::{IIKeyingChunkBody};
    use parse::{GenerateBytes, SliceWriter, VecSliceWriter};
    use crate::session_key_components::{Decode, SessionKeyingComponent};

    #[test]
    pub fn iikeying_round_trip() {
        let packet = IIKeyingChunkBody {
            initiator_session_id: 0,
            cookie_length: 0.into(),
            cookie_echo: Vec::new(),
            cert_length: 0.into(),
            initiator_certificate: FlashCertificate {
                canonical: Vec::new(),
                remainder: Vec::new(),
            },
            skic_length: 0.into(),
            session_key_initiator_component: SessionKeyingComponent::default(),
            signature: Vec::new(),
            nonce: Vec::new(),
        };
        let mut sw = VecSliceWriter::default();
        packet.generate(&mut sw);
        let (i, dec) = IIKeyingChunkBody::decode(&sw.as_slice()).unwrap();
        assert_eq!(dec, packet);
        assert_eq!(i, &[]);
    }
}
