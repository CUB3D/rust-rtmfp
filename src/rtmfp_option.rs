use crate::encode_raw;
use crate::session_key_components::{Decode, Encode};
use crate::vlu::VLU;
use crate::StaticEncode;
use cookie_factory::sequence::tuple;
use cookie_factory::{GenResult, SerializeFn, WriteContext};
use std::io::Write;

#[derive(Debug, Clone)]
pub enum RTMFPOption {
    Marker,
    Option {
        length: VLU,
        type_: VLU,
        value: Vec<u8>,
    },
}

impl Decode for RTMFPOption {
    fn decode(i: &[u8]) -> nom::IResult<&[u8], Self> {
        let (i, length) = VLU::decode(i)?;

        if length.value == 0 {
            Ok((i, RTMFPOption::Marker))
        } else {
            let (i, type_) = VLU::decode(i)?;
            let (i, value) = nom::bytes::complete::take(length.value - type_.length as u64)(i)?;
            Ok((
                i,
                RTMFPOption::Option {
                    length,
                    type_,
                    value: value.to_vec(),
                },
            ))
        }
    }
}

impl RTMFPOption {
    pub fn encode_impl<'a, W: Write + 'a>(&'a self) -> impl SerializeFn<W> + 'a {
        move |out| match self {
            RTMFPOption::Marker => VLU::from(0).encode()(out),
            RTMFPOption::Option {
                value,
                type_,
                length,
            } => tuple((length.encode(), type_.encode(), encode_raw(value)))(out),
        }
    }

    pub fn is_marker(&self) -> bool {
        matches!(self, RTMFPOption::Marker)
    }
}

impl<W: Write> Encode<W> for RTMFPOption {
    fn encode(&self, w: WriteContext<W>) -> GenResult<W> {
        self.encode_impl()(w)
    }
}
static_encode!(RTMFPOption);

pub trait OptionType {
    fn option_type(&self) -> u8;
    fn option_type_vlu(&self) -> VLU {
        self.option_type().into()
    }
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
