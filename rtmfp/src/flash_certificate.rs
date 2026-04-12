use crate::encode::StaticEncode;
use crate::rtmfp_option::RTMFPOption;
use crate::session_key_components::Decode;
use crate::OptionType;
use nom::IResult;
use parse::{GenerateBytes, SliceWriter, VecSliceWriter};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FlashCertificate {
    pub canonical: Vec<RTMFPOption>,
    pub remainder: Vec<RTMFPOption>,
}

impl FlashCertificate {
    pub fn decode(i: &[u8]) -> IResult<&[u8], Self> {
        println!("FlashCertificate = {:X?}", i);

        let mut canonical = Vec::new();

        let mut i = i;
        loop {
            let val = RTMFPOption::decode(i);

            match val {
                Ok((j, c)) => {
                    i = j;
                    if c.is_marker() {
                        break;
                    }
                    canonical.push(c);
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
                canonical,
                remainder,
            },
        ))
    }
}

impl StaticEncode for FlashCertificate {
    //TODO: drop
    fn encode_static(&self) -> Vec<u8> {
        let mut sw = VecSliceWriter::default();
        self.generate(&mut sw);
        sw.as_slice().to_vec()
    }
}

impl GenerateBytes for FlashCertificate {
    fn generate<'b>(&'b self, sw: &'b mut impl SliceWriter) {
        sw.gen_many(self.canonical.as_slice());
    }
}

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
impl OptionType for HostnameBody {
    fn option_type(&self) -> u8 {
        CertificateOptions::Hostname as u8
    }
}
impl StaticEncode for HostnameBody {
    //TODO: drop
    fn encode_static(&self) -> Vec<u8> {
        let mut sw = VecSliceWriter::default();
        self.generate(&mut sw);
        sw.as_slice().to_vec()
    }
}
impl GenerateBytes for HostnameBody {
    fn generate<'b>(&'b self, sw: &'b mut impl SliceWriter) {
        sw.put(self.hostname.as_slice());
    }
}

//TODO:revive
// pub struct AcceptsAncillaryDataBody;
// optionable!(
//     AcceptsAncillaryDataBody,
//     CertificateOptions::AcceptsAncillaryData
// );
// impl<T: Write> Encode<T> for AcceptsAncillaryDataBody {
//     fn encode(&self, w: WriteContext<T>) -> GenResult<T> {
//         Ok(w)
//     }
// }

pub struct ExtraRandomnessBody {
    pub extra_randomness: Vec<u8>,
}
impl OptionType for ExtraRandomnessBody {
    fn option_type(&self) -> u8 {
        CertificateOptions::ExtraRandomness as u8
    }
}
impl StaticEncode for ExtraRandomnessBody {
    //TODO: drop
    fn encode_static(&self) -> Vec<u8> {
        let mut sw = VecSliceWriter::default();
        self.generate(&mut sw);
        sw.as_slice().to_vec()
    }
}
impl GenerateBytes for ExtraRandomnessBody {
    fn generate<'b>(&'b self, sw: &'b mut impl SliceWriter) {
        sw.put(self.extra_randomness.as_slice());
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

//TODO: restore
// pub struct SupportedEphemeralDiffieHellmanGroupBody {
//     pub group_id: VLU,
// }
// optionable!(
//     SupportedEphemeralDiffieHellmanGroupBody,
//     CertificateOptions::SupportedEphemeralDiffieHellmanGroup
// );
// impl<T: Write> Encode<T> for SupportedEphemeralDiffieHellmanGroupBody {
//     fn encode(&self, w: WriteContext<T>) -> GenResult<T> {
//         self.group_id.encode()(w)
//     }
// }

//TODO: restore
// pub struct StaticDiffieHellmanPublicKeyBody {
//     pub group_id: VLU,
//     pub public_key: Vec<u8>,
// }
// optionable!(
//     StaticDiffieHellmanPublicKeyBody,
//     CertificateOptions::StaticDiffieHellmanPublicKey
// );
// impl<T: Write> Encode<T> for StaticDiffieHellmanPublicKeyBody {
//     fn encode(&self, w: WriteContext<T>) -> GenResult<T> {
//         tuple((
//             move |out| self.group_id.encode()(out),
//             encode_raw(&self.public_key),
//         ))(w)
//     }
// }
