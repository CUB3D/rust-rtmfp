use crate::rtmfp_option::RTMFPOption;
use crate::session_key_components::{Decode, Encode};
use crate::{StaticEncode, encode_raw};
use cookie_factory::multi::all;
use cookie_factory::{GenResult, WriteContext};
use std::io::Write;
use cookie_factory::sequence::tuple;
use crate::vlu::VLU;
use crate::OptionType;

#[derive(Debug, Clone)]
pub struct FlashCertificate {
    pub cannonical: Vec<RTMFPOption>,
    pub remainder: Vec<RTMFPOption>,
}

impl FlashCertificate {
    pub fn decode(i: &[u8]) -> nom::IResult<&[u8], Self> {
        let mut cannonical = vec![];

        let mut i = i;
        loop {
            let val = RTMFPOption::decode(i);

            match val {
                Ok((j, c)) => {
                    i = j;
                    if c.is_marker() {
                        break;
                    }
                    cannonical.push(c);
                }
                Err(e) => {
                    break;
                }
            }
        }

        let (i, remainder) = nom::multi::many0(RTMFPOption::decode)(i)?;

        Ok((
            i,
            Self {
                cannonical,
                remainder,
            },
        ))
    }
}

impl<W: Write> Encode<W> for FlashCertificate {
    fn encode(&self, w: WriteContext<W>) -> GenResult<W> {
        all(self.cannonical.iter().map(|c| c.encode_impl()))(w)
    }
}
static_encode!(FlashCertificate);

#[repr(u8)]
pub enum CertificateOptions {
    Hostname = 0x00,
    AcceptsAncillaryData = 0x0a,
    ExtraRandomness = 0x0e,
    SupportedEphemeralDiffieHellmanGroup = 0x15,
    StaticDiffieHellmanPublicKey = 0x1d,
}

pub struct HostnameBody {
    pub hostname: Vec<u8>,
}
optionable!(
    HostnameBody,
    CertificateOptions::Hostname
);
impl<T: Write> Encode<T> for HostnameBody {
    fn encode(&self, w: WriteContext<T>) -> GenResult<T> {
        encode_raw(&self.hostname)(w)
    }
}

pub struct AcceptsAncillaryDataBody;
optionable!(
    AcceptsAncillaryDataBody,
    CertificateOptions::AcceptsAncillaryData
);
impl<T: Write> Encode<T> for AcceptsAncillaryDataBody {
    fn encode(&self, w: WriteContext<T>) -> GenResult<T> {
        Ok(w)
    }
}

pub struct ExtraRandomnessBody {
    pub extra_randomness: Vec<u8>,
}
optionable!(
    ExtraRandomnessBody,
    CertificateOptions::ExtraRandomness
);
impl<T: Write> Encode<T> for ExtraRandomnessBody {
    fn encode(&self, w: WriteContext<T>) -> GenResult<T> {
        encode_raw(&self.extra_randomness)(w)
    }
}

pub struct SupportedEphemeralDiffieHellmanGroupBody {
    pub group_id: VLU,
}
optionable!(
    SupportedEphemeralDiffieHellmanGroupBody,
    CertificateOptions::SupportedEphemeralDiffieHellmanGroup
);
impl<T: Write> Encode<T> for SupportedEphemeralDiffieHellmanGroupBody {
    fn encode(&self, w: WriteContext<T>) -> GenResult<T> {
        self.group_id.encode()(w)
    }
}

pub struct StaticDiffieHellmanPublicKeyBody {
    pub group_id: VLU,
    pub public_key: Vec<u8>,
}
optionable!(
    StaticDiffieHellmanPublicKeyBody,
    CertificateOptions::StaticDiffieHellmanPublicKey
);
impl<T: Write> Encode<T> for StaticDiffieHellmanPublicKeyBody {
    fn encode(&self, w: WriteContext<T>) -> GenResult<T> {
        tuple((move |out| self.group_id.encode()(out), encode_raw(&self.public_key)))(w)
    }
}
