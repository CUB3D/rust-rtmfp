use crate::error::RtmfpError;
use crate::session_key_components::Decode;
use crate::vlu::VLU;
use crate::StaticEncode;
use parse::{take, GenerateBytes, ParseBytes, SliceWriter};

/// RFC7016[2.1.3] Option
/// This is a Length-Type-Value triple, encoded with [`VLU`]s
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum RTMFPOption {
    /// A VLU with a length of 0: has no type and value and is called a Marker
    Marker,
    Option {
        length: VLU,
        type_: VLU,
        value: Vec<u8>,
    },
}

impl RTMFPOption {
    pub fn from_type_and_slice(type_: VLU, slice: &[u8]) -> Self {
        Self::Option {type_, value: slice.to_vec(), length: VLU::from(type_.length as usize + slice.len())}
    }
}

impl GenerateBytes for RTMFPOption {
    fn generate<'b>(&'b self, sw: &'b mut impl SliceWriter) {
        match self {
            Self::Marker => VLU::from(0).generate(sw),
            Self::Option { length, type_, value } => {
                length.generate(sw);
                type_.generate(sw);
                sw.put(value.as_slice());
            }
        }
    }
}

impl ParseBytes<'_> for RTMFPOption {
    type Error = RtmfpError;

    fn parse(i: &[u8]) -> Result<(&[u8], Self), Self::Error>
    where
        Self: Sized
    {
        let (i, length) = VLU::parse(i)?;

        if length.value == 0 {
            Ok((i, RTMFPOption::Marker))
        } else {
            let (i, type_) = VLU::parse(i)?;
            let (i, value) = take(i, (length.value - type_.length as u64) as usize)?;
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

impl Decode for RTMFPOption {
    fn decode(i: &[u8]) -> nom::IResult<&[u8], Self> {
        let (i, length) = VLU::parse(i)?;

        if length.value == 0 {
            Ok((i, RTMFPOption::Marker))
        } else {
            let (i, type_) = VLU::parse(i)?;
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
