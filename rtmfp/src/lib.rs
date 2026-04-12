extern crate core;
#[macro_use]
extern crate derive_try_from_primitive;
#[macro_use]
extern crate enumset;

pub use crate::chunk_ihello::IHelloChunkBody;
pub use crate::chunk_iikeying::IIKeyingChunkBody;
pub use crate::chunk_ping::PingBody;
pub use crate::chunk_ping_reply::PingReplyBody;
pub use crate::chunk_rhello::RHelloChunkBody;
use crate::encode::StaticEncode;


use crate::rtmfp_option::OptionType;
use crate::rtmfp_option::RTMFPOption;

use crate::chunk_content::ChunkContent;

#[macro_export]
macro_rules! optionable {
    ($name: ident, $type_: expr) => {
        static_encode!($name);

        impl OptionType for $name {
            fn option_type(&self) -> u8 {
                $type_ as u8
            }
        }
    };
}

pub mod checksum;
pub mod chunk_ihello;
pub mod chunk_iikeying;
pub mod chunk_ping;
pub mod chunk_ping_reply;
pub mod chunk_rhello;
pub mod chunk_rikeying;
pub mod chunk_session_close_acknowledgement;
pub mod chunk_session_close_request;
pub mod chunk_user_data;
pub mod connection_state_machine;
pub mod encode;
pub mod endpoint_discriminator;
pub mod flash_certificate;
pub mod flash_profile_plain_packet;
pub mod packet_flags;
pub mod rtmfp_option;
pub mod rtmfp_stream;
pub mod session_key_components;
pub mod vlu;
pub mod error;
pub mod multiplex;
pub mod packet;
pub mod chunk_type;
pub mod chunk_content;
pub mod chunk;