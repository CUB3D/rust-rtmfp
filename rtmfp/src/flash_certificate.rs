use crate::encode::StaticEncode;
use crate::error::RtmfpError;
use crate::rtmfp_option::RTMFPOption;
use crate::session_key_components::Decode;
use crate::vlu::VLU;
use nom::IResult;
use parse::{GenerateBytes, ParseBytes, SliceWriter, Take, VecSliceWriter};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FlashCertificate {
    pub canonical: Vec<FlashCertificateCanonicalOption>,
    pub remainder: Vec<RTMFPOption>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum FlashCertificateCanonicalOption {
    Hostname(HostnameBody),
    ExtraRandomness(ExtraRandomnessBody),
    AcceptsAncillaryData(AcceptsAncillaryDataBody),
    SupportedEphemeralDiffieHellmanGroup(SupportedEphemeralDiffieHellmanGroupBody),
    StaticDiffieHellmanPublicKey(StaticDiffieHellmanPublicKeyBody),
}

impl GenerateBytes for FlashCertificateCanonicalOption {
    fn generate<'b>(&'b self, sw: &'b mut impl SliceWriter) {
        let mut sw2 = VecSliceWriter::default();
        let tag = match self {
            FlashCertificateCanonicalOption::Hostname(h) => {
                h.generate(&mut sw2);
                CERTIFICATE_OPTION_HOSTNAME
            }
            FlashCertificateCanonicalOption::ExtraRandomness(h) => {
                h.generate(&mut sw2);
                CERTIFICATE_OPTION_EXTRA_RANDOMNESS
            }
            FlashCertificateCanonicalOption::AcceptsAncillaryData(h) => {
                h.generate(&mut sw2);
                CERTIFICATE_OPTION_ACCEPTS_ANCILLARY_DATA
            }
            FlashCertificateCanonicalOption::SupportedEphemeralDiffieHellmanGroup(h) => {
                h.generate(&mut sw2);
                CERTIFICATE_OPTION_SUPPORTED_DIFFIE_HELLMAN_GROUP
            }
            FlashCertificateCanonicalOption::StaticDiffieHellmanPublicKey(h) => {
                h.generate(&mut sw2);
                CERTIFICATE_OPTION_STATIC_DIFFIE_HELLMAN_PUBLIC_KEY
            }
        };
        RTMFPOption::from_type_and_slice(VLU::from(tag as usize), sw2.as_slice()).generate(sw);
    }
}

impl ParseBytes<'_> for FlashCertificate {
    type Error = RtmfpError;

    fn parse(i: &[u8]) -> Result<(&[u8], Self), Self::Error>
    where
        Self: Sized
    {
        let (_, canonical) = parse::take_until::<_, RtmfpError, _>(i, |i| {
            let op = RTMFPOption::parse(i);
            match op {
                Ok((i, op)) => {
                    match op {
                        RTMFPOption::Marker => {
                            Ok((i, Take::End))
                        }
                        RTMFPOption::Option {length: _, type_, value} => {
                            match type_.value {
                                CERTIFICATE_OPTION_HOSTNAME => {
                                    let body = HostnameBody { hostname: value };
                                    Ok((i, Take::More(FlashCertificateCanonicalOption::Hostname(body))))
                                }
                                CERTIFICATE_OPTION_EXTRA_RANDOMNESS => {
                                    let body = ExtraRandomnessBody { extra_randomness: value };
                                    Ok((i, Take::More(FlashCertificateCanonicalOption::ExtraRandomness(body))))
                                }
                                CERTIFICATE_OPTION_ACCEPTS_ANCILLARY_DATA => {
                                    let body = AcceptsAncillaryDataBody (value);
                                    Ok((i, Take::More(FlashCertificateCanonicalOption::AcceptsAncillaryData(body))))
                                }
                                CERTIFICATE_OPTION_SUPPORTED_DIFFIE_HELLMAN_GROUP => {
                                    let body = SupportedEphemeralDiffieHellmanGroupBody { data: value};
                                    Ok((i, Take::More(FlashCertificateCanonicalOption::SupportedEphemeralDiffieHellmanGroup(body))))
                                }
                                CERTIFICATE_OPTION_STATIC_DIFFIE_HELLMAN_PUBLIC_KEY => {
                                    let body = StaticDiffieHellmanPublicKeyBody { data: value};
                                    Ok((i, Take::More(FlashCertificateCanonicalOption::StaticDiffieHellmanPublicKey(body))))
                                }
                                _ => {
                                    panic!("Option: {}", type_.value);
                                }
                            }
                        }
                    }
                }
                Err(p) => {
                    Ok((i, Take::End))
                }
            }
        })?;
        let (i, remainder) = parse::take_until::<_, RtmfpError, _>(i, |i| {
            let op = RTMFPOption::parse(i);
            match op {
                Ok((i, op)) => {
                    match op {
                        RTMFPOption::Marker => {
                            Ok((i, Take::End))
                        }
                        RTMFPOption::Option {length, type_, value} => {
                            Ok((i, Take::More(RTMFPOption::Option {length, type_, value})))
                        }
                    }
                }
                Err(p) => {
                    //TODO: take_until shuld be while !is_empty
                    Ok((i, Take::End))
                }
            }
        })?;
        Ok((i, Self {
            canonical,
            remainder,
        }))
    }
}

impl GenerateBytes for FlashCertificate {
    fn generate<'b>(&'b self, sw: &'b mut impl SliceWriter) {
        sw.gen_many(self.canonical.as_slice());
    }
}

const CERTIFICATE_OPTION_HOSTNAME: u64 = 0x00;
const CERTIFICATE_OPTION_ACCEPTS_ANCILLARY_DATA: u64 = 0x0A;
const CERTIFICATE_OPTION_EXTRA_RANDOMNESS: u64 = 0x0E;
const CERTIFICATE_OPTION_SUPPORTED_DIFFIE_HELLMAN_GROUP: u64 = 0x15;
const CERTIFICATE_OPTION_STATIC_DIFFIE_HELLMAN_PUBLIC_KEY: u64 = 0x1D;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct HostnameBody {
    pub hostname: Vec<u8>,
}
impl GenerateBytes for HostnameBody {
    fn generate<'b>(&'b self, sw: &'b mut impl SliceWriter) {
        sw.put(self.hostname.as_slice());
    }
}

//TODO:revive
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AcceptsAncillaryDataBody(Vec<u8>);
impl GenerateBytes for AcceptsAncillaryDataBody {
    fn generate<'b>(&'b self, sw: &'b mut impl SliceWriter) {
        sw.put(self.0.as_slice());
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ExtraRandomnessBody {
    pub extra_randomness: Vec<u8>,
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
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SupportedEphemeralDiffieHellmanGroupBody {
    pub data: Vec<u8>,
    // pub group_id: VLU,
}
impl GenerateBytes for SupportedEphemeralDiffieHellmanGroupBody {
    fn generate<'b>(&'b self, sw: &'b mut impl SliceWriter) {
        sw.put(self.data.as_slice());
    }
}


//TODO: restore
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct StaticDiffieHellmanPublicKeyBody {
    pub data: Vec<u8>,
}
impl GenerateBytes for StaticDiffieHellmanPublicKeyBody {
    fn generate<'b>(&'b self, sw: &'b mut impl SliceWriter) {
        sw.put(self.data.as_slice());
    }
}
//     pub group_id: VLU,
//     pub public_key: Vec<u8>,
// }
