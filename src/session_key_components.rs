use crate::static_encode;
use crate::vlu::VLU;
use crate::OptionType;
use crate::{encode_raw, RTMFPOption, StaticEncode};
use cookie_factory::bytes::be_u8;
use cookie_factory::sequence::tuple;
use cookie_factory::{GenResult, WriteContext};
use std::io::Write;

pub trait Encode<W> {
    fn encode(&self, w: WriteContext<W>) -> GenResult<W>;
}

pub trait Decode: Sized {
    fn decode(i: &[u8]) -> nom::IResult<&[u8], Self>;
}

pub type SessionKeyingComponent = Vec<RTMFPOption>;

impl<W: Write, T: Encode<W>> Encode<W> for Vec<T> {
    fn encode(&self, w: WriteContext<W>) -> GenResult<W> {
        cookie_factory::multi::all(self.iter().map(|t| move |out| t.encode(out)))(w)
    }
}
static_encode!(SessionKeyingComponent);

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
        cookie_factory::sequence::tuple((self.group_id.encode(), encode_raw(&self.public_key)))(w)
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
