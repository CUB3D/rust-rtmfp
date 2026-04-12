use parse::{GenerateBytes, SliceWriter};
use crate::{IHelloChunkBody, IIKeyingChunkBody, PingBody, PingReplyBody, RHelloChunkBody};
use crate::chunk_rikeying::ResponderInitialKeyingChunkBody;
use crate::chunk_session_close_acknowledgement::SessionCloseAcknowledgementBody;
use crate::chunk_session_close_request::SessionCloseRequestBody;
use crate::chunk_type::ChunkType;
use crate::chunk_user_data::UserDataChunk;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ChunkContent {
    Raw(Vec<u8>),
    IHello(IHelloChunkBody),
    RHello(RHelloChunkBody),
    IIKeying(IIKeyingChunkBody),
    RIKeying(ResponderInitialKeyingChunkBody),
    Ping(PingBody),
    PingReply(PingReplyBody),
    SessionCloseRequest(SessionCloseRequestBody),
    SessionCloseAcknowledgement(SessionCloseAcknowledgementBody),
    UserData(UserDataChunk),
}
impl From<ChunkContent> for ChunkType {
    fn from(s: ChunkContent) -> Self {
        match s {
            ChunkContent::Raw(_) => unimplemented!(),
            ChunkContent::RHello(_) => ChunkType::ResponderHello,
            ChunkContent::IHello(_) => ChunkType::InitiatorHello,
            ChunkContent::IIKeying(_) => ChunkType::InitiatorInitialKeying,
            ChunkContent::RIKeying(_) => ChunkType::ResponderInitialKeying,
            ChunkContent::Ping(_) => ChunkType::Ping,
            ChunkContent::PingReply(_) => ChunkType::PingReply,
            ChunkContent::SessionCloseRequest(_) => ChunkType::SessionCloseRequest,
            ChunkContent::SessionCloseAcknowledgement(_) => ChunkType::SessionCloseAcknowledgement,
            ChunkContent::UserData(_) => ChunkType::UserData,
        }
    }
}

impl GenerateBytes for ChunkContent {
    fn generate<'b>(&'b self, sw: &'b mut impl SliceWriter) {
        match self {
            ChunkContent::Raw(v) => {
                sw.put(v.as_slice());
            },
            ChunkContent::RHello(body) => {
                body.generate(sw);
            }
            ChunkContent::IIKeying(body) => {
                body.generate(sw);
            }
            ChunkContent::IHello(body) => {
                body.generate(sw);
            }
            ChunkContent::RIKeying(body) => {
                body.generate(sw);
            }
            ChunkContent::Ping(body) => {
                body.generate(sw);
            },
            ChunkContent::PingReply(body) => {
                body.generate(sw);
            },
            ChunkContent::SessionCloseRequest(body) => {
                body.generate(sw);
            },
            ChunkContent::SessionCloseAcknowledgement(body) => {
                body.generate(sw);
            },
            ChunkContent::UserData(body) => {
                body.generate(sw);
            },
        }
    }
}

impl ChunkContent {
    pub fn get_rhello(&self) -> Option<RHelloChunkBody> {
        match self {
            ChunkContent::RHello(body) => Some(body.clone()),
            _ => None,
        }
    }

    pub fn get_rikeying(&self) -> Option<ResponderInitialKeyingChunkBody> {
        match self {
            ChunkContent::RIKeying(body) => Some(body.clone()),
            _ => None,
        }
    }
}