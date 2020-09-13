use crate::encode::Encode;
use crate::endpoint_discriminator::EndpointDiscriminator;
use crate::flash_certificate::FlashCertificate;
use crate::session_key_components::{Decode, SessionKeyingComponent};
use crate::vlu::VLU;
use crate::StaticEncode;
use crate::{encode_raw, ChunkContent};
use cookie_factory::bytes::{be_u32, be_u8};
use cookie_factory::sequence::tuple;
use cookie_factory::{GenResult, WriteContext};
use nom::IResult;
use std::io::Write;

#[derive(Debug, Clone)]
pub struct IIKeyingChunkBody {
    pub initiator_session_id: u32,
    pub cookie_length: VLU,
    pub cookie_echo: Vec<u8>,
    pub cert_length: VLU,
    pub initiator_certificate: FlashCertificate,
    pub skic_length: VLU,
    pub session_key_initiator_component: SessionKeyingComponent,
    pub signature: Vec<u8>,
}

impl IIKeyingChunkBody {
    pub fn new(
        session_id: u32,
        cookie: Vec<u8>,
        certificate: FlashCertificate,
        skic: SessionKeyingComponent,
    ) -> Self {
        let cert_size = certificate.encode_static().len();
        let skic_length = skic.encode_static().len();

        Self {
            initiator_session_id: session_id,
            cookie_length: cookie.len().into(),
            cookie_echo: cookie,
            cert_length: cert_size.into(),
            initiator_certificate: certificate,
            skic_length: skic_length.into(),
            session_key_initiator_component: skic,
            signature: vec![],
        }
    }
}
impl<T: Write> Encode<T> for IIKeyingChunkBody {
    fn encode(&self, w: WriteContext<T>) -> GenResult<T> {
        tuple((
            be_u32(self.initiator_session_id),
            self.cookie_length.encode(),
            encode_raw(&self.cookie_echo),
            self.cert_length.encode(),
            //TODO: compute above length
            move |out| self.initiator_certificate.encode(out),
            self.skic_length.encode(),
            move |out| self.session_key_initiator_component.encode(out),
            encode_raw(&self.signature),
        ))(w)
    }
}
static_encode!(IIKeyingChunkBody);

impl Decode for IIKeyingChunkBody {
    fn decode(i: &[u8]) -> IResult<&[u8], Self> {
        let (i, initiator_session_id) = nom::number::complete::be_u32(i)?;
        let (i, cookie_length) = VLU::decode(i)?;
        let cookie = &i[..cookie_length.value as usize];

        let i = &i[cookie_length.value as usize..];
        let (i, cert_length) = VLU::decode(i)?;
        let cert_data = &i[..cert_length.value as usize];
        let (_cert_rem, initiator_certificate) = FlashCertificate::decode(cert_data)?;

        let i = &i[cert_length.value as usize..];
        let (i, skic_length) = VLU::decode(i)?;
        let skic_data = &i[..skic_length.value as usize];
        let (_skik_rem, session_key_initiator_component) =
            SessionKeyingComponent::decode(skic_data)?;

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
            },
        ))
    }
}

impl From<IIKeyingChunkBody> for ChunkContent {
    fn from(s: IIKeyingChunkBody) -> Self {
        ChunkContent::IIKeying(s)
    }
}
