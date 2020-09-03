use crate::rtmfp_option::RTMFPOption;
use crate::session_key_components::{Decode, Encode};
use crate::StaticEncode;
use cookie_factory::multi::all;
use cookie_factory::{GenResult, WriteContext};
use std::io::Write;

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
