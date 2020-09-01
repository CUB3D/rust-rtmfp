use crate::vlu::VLU;
use crate::RTMFPOption;

type SessionKeyingComponent = Vec<RTMFPOption>;

#[derive(Debug)]
#[repr(u8)]
pub enum SessionKeyingOptionTypes {
    EphemeralDiffieHellmanPublicKey = 0x0d,
    ExtraRandomness = 0x0e,
    DiffieHellmanGroupSelect = 0x1d,
    HMACNegotiation = 0x1a,
    SessionSequenceNumberNegotiation = 0x1e,
}

#[derive(Debug)]
pub struct EphemeralDiffieHellmanPublicKey {
    pub group_id: VLU,
    pub public_key: Vec<u8>,
}

#[derive(Debug)]
pub struct ExtraRandomness {
    pub extra_randomness: Vec<u8>,
}

#[derive(Debug)]
pub struct DiffieHellmanGroupSelect {
    pub group_id: VLU,
}

#[derive(Debug)]
pub struct HMACNegotiation {
    /// [0:4] reserved
    /// [5] will send always
    /// [6] will send on request
    /// [6] request
    pub flags: u8,
    pub hmac_length: VLU,
}

#[derive(Debug)]
pub struct SessionSequenceNumberNegotiation {
    /// [0:4] reserved
    /// [5] will send always
    /// [6] will send on request
    /// [6] request
    pub flags: u8,
}
