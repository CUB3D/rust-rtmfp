use crate::vlu::VLU;
use crate::{encode_raw, RTMFPOption};
use cookie_factory::bytes::be_u8;
use cookie_factory::sequence::tuple;
use cookie_factory::{GenResult, SerializeFn, WriteContext};
use std::io::Write;

pub trait Encode<W> {
    fn encode(&self, w: WriteContext<W>) -> GenResult<W>;
}

pub trait StaticEncode {
    fn encode_static(&self) -> Vec<u8>;
}

pub trait OptionType {
    fn option_type(&self) -> u8;
    fn option_type_vlu(&self) -> VLU {
        self.option_type().into()
    }
}

macro_rules! optionable {
    ($name: ident, $type_: expr) => {
        impl OptionType for $name {
            fn option_type(&self) -> u8 {
                $type_ as u8
            }
        }

        impl StaticEncode for $name {
            fn encode_static(&self) -> Vec<u8> {
                let v = vec![];
                let (bytes, size) = cookie_factory::gen(move |out| self.encode(out), v).unwrap();
                bytes
            }
        }
    };
}

impl<T: OptionType + StaticEncode> From<T> for RTMFPOption {
    fn from(t: T) -> Self {
        let type_vlu = t.option_type_vlu();
        let data = t.encode_static();
        RTMFPOption::Option {
            type_: type_vlu,
            length: ((type_vlu.length + data.len() as u8) as u8).into(),
            value: data,
        }
    }
}

pub type SessionKeyingComponent = Vec<RTMFPOption>;

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
