use crate::rtmfp_option::RTMFPOption;
use crate::session_key_components::Encode;
use crate::StaticEncode;
use crate::{encode_raw, OptionType};
use cookie_factory::{GenResult, WriteContext};
use nom::AsBytes;
use std::io::Write;

pub type EndpointDiscriminator = Vec<RTMFPOption>;

#[repr(u8)]
pub enum EndpointDiscriminatorOptionTypes {
    RequiredHostname = 0x00,
    AncillaryData = 0x0a,
    Fingerprint = 0x0f,
}

pub struct RequiredHostnameBody {
    pub hostname: Vec<u8>,
}
optionable!(
    RequiredHostnameBody,
    EndpointDiscriminatorOptionTypes::RequiredHostname
);
impl<T: Write> Encode<T> for RequiredHostnameBody {
    fn encode(&self, w: WriteContext<T>) -> GenResult<T> {
        encode_raw(&self.hostname)(w)
    }
}

pub struct AncillaryDataBody {
    pub ancillary_data: Vec<u8>,
}
optionable!(
    AncillaryDataBody,
    EndpointDiscriminatorOptionTypes::AncillaryData
);
impl<T: Write> Encode<T> for AncillaryDataBody {
    fn encode(&self, w: WriteContext<T>) -> GenResult<T> {
        encode_raw(&self.ancillary_data)(w)
    }
}

pub struct FingerprintBody {
    pub fingerprint: [u8; 32],
}
optionable!(
    FingerprintBody,
    EndpointDiscriminatorOptionTypes::Fingerprint
);
impl<T: Write> Encode<T> for FingerprintBody {
    fn encode(&self, w: WriteContext<T>) -> GenResult<T> {
        encode_raw(self.fingerprint.as_bytes())(w)
    }
}
