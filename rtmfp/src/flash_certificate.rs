use crate::encode::Encode;
use crate::rtmfp_option::RTMFPOption;
use crate::session_key_components::Decode;
use crate::vlu::VLU;
use crate::OptionType;
use crate::{encode_raw};
use cookie_factory::multi::all;
use cookie_factory::sequence::tuple;
use cookie_factory::{GenResult, WriteContext};
use nom::IResult;
use std::io::Write;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FlashCertificate {
    pub cannonical: Vec<RTMFPOption>,
    pub remainder: Vec<RTMFPOption>,
}

impl FlashCertificate {
    pub fn decode(i: &[u8]) -> nom::IResult<&[u8], Self> {
        println!("FlashCertificate = {:X?}", i);

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
                Err(_e) => {
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

pub fn get_extra_randomness(s: Vec<RTMFPOption>) -> Option<ExtraRandomnessBody> {
    s.iter()
        .find(|o| match o {
            RTMFPOption::Option {
                type_,
                length: _length,
                value: _value,
            } => type_.value == CertificateOptions::ExtraRandomness as u64,
            _ => false,
        })
        .map(|o| {
            ExtraRandomnessBody::decode(&o.value().unwrap())
                .map(|o| o.1)
                .unwrap()
        })
}

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
optionable!(HostnameBody, CertificateOptions::Hostname);
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
optionable!(ExtraRandomnessBody, CertificateOptions::ExtraRandomness);
impl<T: Write> Encode<T> for ExtraRandomnessBody {
    fn encode(&self, w: WriteContext<T>) -> GenResult<T> {
        encode_raw(&self.extra_randomness)(w)
    }
}
impl Decode for ExtraRandomnessBody {
    fn decode(i: &[u8]) -> IResult<&[u8], Self> {
        Ok((
            &[],
            Self {
                extra_randomness: i.to_vec(),
            },
        ))
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
        tuple((
            move |out| self.group_id.encode()(out),
            encode_raw(&self.public_key),
        ))(w)
    }
}
