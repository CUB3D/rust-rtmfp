use crate::encode::Encode;
use crate::encode_raw;
use crate::session_key_components::Decode;
use crate::vlu::VLU;
use crate::StaticEncode;
use cookie_factory::sequence::tuple;
use cookie_factory::{GenResult, SerializeFn, WriteContext};
use std::io::Write;

#[derive(Debug, Clone, Eq, PartialEq)]
/// RFC7016[2.1.3] Option
/// This is a Length-Type-Value triple, encoded with [`VLU`]s
pub enum RTMFPOption {
    /// A VLU with a length of 0: has no type and value and is called a Marker
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

    pub fn value(&self) -> Option<Vec<u8>> {
        match self {
            RTMFPOption::Option {
                value,
                type_: _type_,
                length: _length,
            } => Some(value.clone()),
            _ => None,
        }
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
        let len = type_vlu.length as u64 + data.len() as u64;
        if len > 255 {
            panic!();
        }

        RTMFPOption::Option {
            type_: type_vlu,
            length: (len as u8).into(),
            value: data,
        }
    }
}
