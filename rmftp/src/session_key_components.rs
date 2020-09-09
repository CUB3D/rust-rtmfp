use crate::static_encode;
use crate::vlu::VLU;
use crate::OptionType;
use crate::{encode_raw, RTMFPOption, StaticEncode};
use cookie_factory::bytes::be_u8;
use cookie_factory::sequence::tuple;
use cookie_factory::{GenResult, WriteContext};
use nom::IResult;
use std::io::Write;

pub trait Encode<W> {
    fn encode(&self, w: WriteContext<W>) -> GenResult<W>;
}
impl<W: Write, T: Encode<W>> Encode<W> for Vec<T> {
    fn encode(&self, w: WriteContext<W>) -> GenResult<W> {
        cookie_factory::multi::all(self.iter().map(|t| move |out| t.encode(out)))(w)
    }
}

pub trait Decode: Sized {
    fn decode(i: &[u8]) -> nom::IResult<&[u8], Self>;
}
impl<T: Decode> Decode for Vec<T> {
    fn decode(i: &[u8]) -> IResult<&[u8], Self> {
        nom::multi::many0(T::decode)(i)
    }
}

pub type SessionKeyingComponent = Vec<RTMFPOption>;
static_encode!(SessionKeyingComponent);
pub fn get_epehemeral_diffie_hellman_public_key(
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

pub fn get_extra_randomness(
    s: Vec<RTMFPOption>,
) -> Option<ExtraRandomnessBody> {
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
optionable!(
    EphemeralDiffieHellmanPublicKeyBody,
    SessionKeyingOptionTypes::EphemeralDiffieHellmanPublicKey
);
impl<W: Write> Encode<W> for EphemeralDiffieHellmanPublicKeyBody {
    fn encode(&self, w: WriteContext<W>) -> GenResult<W> {
        cookie_factory::sequence::tuple((self.group_id.encode(), be_u8(0), encode_raw(&self.public_key)))(w)
    }
}
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
optionable!(
    ExtraRandomnessBody,
    SessionKeyingOptionTypes::ExtraRandomness
);

impl<W: Write> Encode<W> for ExtraRandomnessBody {
    fn encode(&self, w: WriteContext<W>) -> GenResult<W> {
        encode_raw(&self.extra_randomness)(w)
    }
}
impl Decode for ExtraRandomnessBody {
    fn decode(i: &[u8]) -> IResult<&[u8], Self> {
        Ok((&[], Self {
            extra_randomness: i.to_vec()
        }))
    }
}

#[derive(Debug)]
pub struct DiffieHellmanGroupSelectBody {
    pub group_id: VLU,
}
optionable!(
    DiffieHellmanGroupSelectBody,
    SessionKeyingOptionTypes::DiffieHellmanGroupSelect
);

impl<W: Write> Encode<W> for DiffieHellmanGroupSelectBody {
    fn encode(&self, w: WriteContext<W>) -> GenResult<W> {
        self.group_id.encode()(w)
    }
}

#[derive(Debug)]
pub struct HMACNegotiationBody {
    /// [0:4] reserved
    /// [5] will send always
    /// [6] will send on request
    /// [6] request
    pub flags: u8,
    pub hmac_length: VLU,
}
optionable!(
    HMACNegotiationBody,
    SessionKeyingOptionTypes::HMACNegotiation
);

impl<W: Write> Encode<W> for HMACNegotiationBody {
    fn encode(&self, w: WriteContext<W>) -> GenResult<W> {
        tuple((be_u8(self.flags), self.hmac_length.encode()))(w)
    }
}

#[derive(Debug)]
pub struct SessionSequenceNumberNegotiationBody {
    /// [0:4] reserved
    /// [5] will send always
    /// [6] will send on request
    /// [6] request
    pub flags: u8,
}
optionable!(
    SessionSequenceNumberNegotiationBody,
    SessionKeyingOptionTypes::SessionSequenceNumberNegotiation
);

impl<W: Write> Encode<W> for SessionSequenceNumberNegotiationBody {
    fn encode(&self, w: WriteContext<W>) -> GenResult<W> {
        tuple((be_u8(self.flags),))(w)
    }
}
