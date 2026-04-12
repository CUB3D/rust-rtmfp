use crate::encode::StaticEncode;
use crate::rtmfp_option::RTMFPOption;
use crate::vlu::VLU;
use crate::ChunkContent;
use enumset::EnumSet;
use parse::{GenerateBytes, SliceWriter, VecSliceWriter};

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

impl StaticEncode for UserDataChunk {
    //TODO: drop
    fn encode_static(&self) -> Vec<u8> {
        let mut sw = VecSliceWriter::default();
        self.generate(&mut sw);
        sw.as_slice().to_vec()
    }
}

impl GenerateBytes for UserDataChunk {
    fn generate<'b>(&'b self, sw: &'b mut impl SliceWriter) {
        sw.ne_u8(0b1_0_01_00_0_0);
        self.flow_id.generate(sw);
        self.sequence_number.generate(sw);
        self.forward_sequence_number_offset.generate(sw);
        sw.gen_many(self.options.as_slice());
        RTMFPOption::Marker.generate(sw);
        sw.put(self.user_data.as_slice());
    }
}

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
