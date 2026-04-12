use crate::encode::StaticEncode;
use crate::error::RtmfpError;
use crate::vlu::VLU;
use crate::OptionType;
use crate::RTMFPOption;
use nom::IResult;
use parse::{take_all, GenerateBytes, ParseBytes, SliceWriter, VecSliceWriter};

pub trait Decode: Sized {
    fn decode(i: &[u8]) -> IResult<&[u8], Self>;
}
impl<T: Decode> Decode for Vec<T> {
    fn decode(i: &[u8]) -> IResult<&[u8], Self> {
        nom::multi::many0(T::decode)(i)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct SessionKeyingComponent(pub Vec<RTMFPOption>);
impl GenerateBytes for SessionKeyingComponent {
    fn generate<'b>(&'b self, sw: &'b mut impl SliceWriter) {
        sw.gen_many(&self.0.as_slice());
    }
}
impl ParseBytes<'_> for SessionKeyingComponent {
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
impl StaticEncode for SessionKeyingComponent {
    //TODO: drop
    fn encode_static(&self) -> Vec<u8> {
        let mut sw = VecSliceWriter::default();
        self.generate(&mut sw);
        sw.as_slice().to_vec()
    }
}

pub fn get_ephemeral_diffie_hellman_public_key(
    s: Vec<RTMFPOption>,
) -> Option<EphemeralDiffieHellmanPublicKeyBody> {
    s.iter()
        .find(|o| match o {
            RTMFPOption::Option {
                type_,
                length: _length,
                value: _value,
            } => type_.value == SessionKeyingOptionTypes::EphemeralDiffieHellmanPublicKey as u64,
            _ => false,
        })
        .map(|o| {
            EphemeralDiffieHellmanPublicKeyBody::decode(&o.value().unwrap())
                .map(|o| o.1)
                .unwrap()
        })
}

pub fn get_extra_randomness(s: Vec<RTMFPOption>) -> Option<ExtraRandomnessBody> {
    s.iter()
        .find(|o| match o {
            RTMFPOption::Option {
                type_,
                length: _length,
                value: _value,
            } => type_.value == SessionKeyingOptionTypes::ExtraRandomness as u64,
            _ => false,
        })
        .map(|o| {
            ExtraRandomnessBody::decode(&o.value().unwrap())
                .map(|o| o.1)
                .unwrap()
        })
}

#[derive(Debug)]
#[repr(u8)]
pub enum SessionKeyingOptionTypes {
    EphemeralDiffieHellmanPublicKey = 0x0d,
    ExtraRandomness = 0x0e,
    DiffieHellmanGroupSelect = 0x1d,
    HMACNegotiation = 0x1a,
    SessionSequenceNumberNegotiation = 0x1e,
}

impl From<SessionKeyingOptionTypes> for VLU {
    fn from(this: SessionKeyingOptionTypes) -> Self {
        VLU::from(this as u8)
    }
}

#[derive(Debug)]
pub struct EphemeralDiffieHellmanPublicKeyBody {
    pub group_id: VLU,
    pub public_key: Vec<u8>,
}
impl StaticEncode for EphemeralDiffieHellmanPublicKeyBody {
    //TODO: drop
    fn encode_static(&self) -> Vec<u8> {
        let mut sw = VecSliceWriter::default();
        self.generate(&mut sw);
        sw.as_slice().to_vec()
    }
}

impl GenerateBytes for EphemeralDiffieHellmanPublicKeyBody {
    fn generate<'b>(&'b self, sw: &'b mut impl SliceWriter) {
        self.group_id.generate(sw);
        sw.put(self.public_key.as_slice());
    }
}
impl OptionType for EphemeralDiffieHellmanPublicKeyBody {
    fn option_type(&self) -> u8 {
        SessionKeyingOptionTypes::EphemeralDiffieHellmanPublicKey as u8
    }
}
// optionable!(
//     EphemeralDiffieHellmanPublicKeyBody,
//     SessionKeyingOptionTypes::EphemeralDiffieHellmanPublicKey
// );
// impl<W: Write> Encode<W> for EphemeralDiffieHellmanPublicKeyBody {
//     fn encode(&self, w: WriteContext<W>) -> GenResult<W> {
//         tuple((
//             self.group_id.encode(),
//             //TODO:
//             encode_raw(&self.public_key),
//         ))(w)
//     }
// }
impl Decode for EphemeralDiffieHellmanPublicKeyBody {
    fn decode(i: &[u8]) -> IResult<&[u8], Self> {
        let (i, group_id) = VLU::decode(i)?;
        let public_key = i.to_vec();

        Ok((
            &[],
            Self {
                group_id,
                public_key,
            },
        ))
    }
}

#[derive(Debug)]
pub struct ExtraRandomnessBody {
    pub extra_randomness: Vec<u8>,
}
impl OptionType for ExtraRandomnessBody {
    fn option_type(&self) -> u8 {
        SessionKeyingOptionTypes::ExtraRandomness as u8
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
// #[derive(Debug)]
// pub struct DiffieHellmanGroupSelectBody {
//     pub group_id: VLU,
// }
// optionable!(
//     DiffieHellmanGroupSelectBody,
//     SessionKeyingOptionTypes::DiffieHellmanGroupSelect
// );
//
// impl<W: Write> Encode<W> for DiffieHellmanGroupSelectBody {
//     fn encode(&self, w: WriteContext<W>) -> GenResult<W> {
//         self.group_id.encode()(w)
//     }
// }

//TODO: restore
// #[derive(Debug)]
// pub struct HMACNegotiationBody {
//     /// [0:4] reserved
//     /// [5] will send always
//     /// [6] will send on request
//     /// [6] request
//     pub flags: u8,
//     pub hmac_length: VLU,
// }
// optionable!(
//     HMACNegotiationBody,
//     SessionKeyingOptionTypes::HMACNegotiation
// );
//
// impl<W: Write> Encode<W> for HMACNegotiationBody {
//     fn encode(&self, w: WriteContext<W>) -> GenResult<W> {
//         tuple((be_u8(self.flags), self.hmac_length.encode()))(w)
//     }
// }

//TODO: revive
// #[derive(Debug)]
// pub struct SessionSequenceNumberNegotiationBody {
//     /// [0:4] reserved
//     /// [5] will send always
//     /// [6] will send on request
//     /// [6] request
//     pub flags: u8,
// }
// optionable!(
//     SessionSequenceNumberNegotiationBody,
//     SessionKeyingOptionTypes::SessionSequenceNumberNegotiation
// );
//
// impl<W: Write> Encode<W> for SessionSequenceNumberNegotiationBody {
//     fn encode(&self, w: WriteContext<W>) -> GenResult<W> {
//         tuple((be_u8(self.flags),))(w)
//     }
// }
