use crate::encode::Encode;
use crate::rtmfp_option::RTMFPOption;
use crate::vlu::VLU;
use crate::{ChunkContent};
use cookie_factory::bytes::be_u8;
use cookie_factory::multi::all;
use cookie_factory::sequence::tuple;
use cookie_factory::{GenResult, WriteContext};
use enumset::EnumSet;
use std::io::Write;

#[repr(u8)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum UserDataChunkFragmentControl {
    Whole = 0,
    Begin = 1,
    End = 2,
    Middle = 3,
}

#[derive(EnumSetType, Debug)]
pub enum UserDataChunkFlag {
    OptionsPresent,
    Abandon,
    Final,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UserDataChunkFlags {
    pub fragment_control: UserDataChunkFragmentControl,
    pub flags: EnumSet<UserDataChunkFlag>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UserDataChunk {
    pub flags: UserDataChunkFlags,
    pub flow_id: VLU,
    pub sequence_number: VLU,
    pub forward_sequence_number_offset: VLU,
    pub options: Vec<RTMFPOption>,
    pub user_data: Vec<u8>,
}
impl<T: Write> Encode<T> for UserDataChunk {
    fn encode(&self, w: WriteContext<T>) -> GenResult<T> {
        tuple((
            be_u8(0b1_0_01_00_0_0),
            self.flow_id.encode(),
            self.sequence_number.encode(),
            self.forward_sequence_number_offset.encode(),
            all(self.options.iter().map(|x| x.encode_impl())),
            RTMFPOption::Marker.encode_impl(),
            move |out| self.user_data.encode(out),
        ))(w)
    }
}
static_encode!(UserDataChunk);
impl From<UserDataChunk> for ChunkContent {
    fn from(s: UserDataChunk) -> Self {
        ChunkContent::UserData(s)
    }
}

#[repr(u8)]
pub enum UserDataChunkOptionType {
    PerFlowMetadata = 0x00,
    ReturnFlowAssociation = 0x0a,
}
