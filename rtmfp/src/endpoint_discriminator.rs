use crate::encode::StaticEncode;
use crate::error::RtmfpError;
use crate::rtmfp_option::RTMFPOption;
use crate::OptionType;
use parse::{take_all, GenerateBytes, ParseBytes, SliceWriter, VecSliceWriter};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EndpointDiscriminator(pub Vec<RTMFPOption>);

impl GenerateBytes for EndpointDiscriminator {
    fn generate<'b>(&'b self, sw: &'b mut impl SliceWriter) {
        sw.gen_many(self.0.as_slice());
    }
}

impl ParseBytes<'_> for EndpointDiscriminator {
    type Error = RtmfpError;

    fn parse(i: &[u8]) -> Result<(&[u8], Self), Self::Error>
    where
        Self: Sized
    {
        let x = take_all::<_, RtmfpError, _>(i, |i| {
            let (i, x) = RTMFPOption::parse(i)?;
            Ok((i, x))
        })?;
        Ok((&[], Self(x)))
    }
}

#[repr(u8)]
pub enum EndpointDiscriminatorOptionTypes {
    RequiredHostname = 0x00,
    AncillaryData = 0x0a,
    Fingerprint = 0x0f,
}

//TODO: revive
// pub struct RequiredHostnameBody {
//     pub hostname: Vec<u8>,
// }
// optionable!(
//     RequiredHostnameBody,
//     EndpointDiscriminatorOptionTypes::RequiredHostname
// );
// impl<T: Write> Encode<T> for RequiredHostnameBody {
//     fn encode(&self, w: WriteContext<T>) -> GenResult<T> {
//         encode_raw(&self.hostname)(w)
//     }
// }

pub struct AncillaryDataBody {
    pub ancillary_data: Vec<u8>,
}
impl OptionType for AncillaryDataBody {
    fn option_type(&self) -> u8 {
        EndpointDiscriminatorOptionTypes::AncillaryData as u8
    }
}

impl StaticEncode for AncillaryDataBody {
    //TODO: drop
    fn encode_static(&self) -> Vec<u8> {
        let mut sw = VecSliceWriter::default();
        self.generate(&mut sw);
        sw.as_slice().to_vec()
    }
}

impl GenerateBytes for AncillaryDataBody {
    fn generate<'b>(&'b self, sw: &'b mut impl SliceWriter) {
        sw.put(self.ancillary_data.as_slice());
    }
}

//TODO: revive
// pub struct FingerprintBody {
//     pub fingerprint: [u8; 32],
// }
// optionable!(
//     FingerprintBody,
//     EndpointDiscriminatorOptionTypes::Fingerprint
// );
// impl<T: Write> Encode<T> for FingerprintBody {
//     fn encode(&self, w: WriteContext<T>) -> GenResult<T> {
//         encode_raw(self.fingerprint.as_bytes())(w)
//     }
// }
