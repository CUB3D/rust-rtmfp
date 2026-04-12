use crate::flash_profile_plain_packet::FlashProfilePlainPacket;
use crate::session_key_components::Decode;
use aes::cipher::block_padding::NoPadding;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use parse::{GenerateBytes, SliceWriter};

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Multiplex {
    pub session_id: u32,
    pub packet: FlashProfilePlainPacket,
    //TODO: no
    pub encryption_key: Option<Vec<u8>>,
}
impl GenerateBytes for Multiplex {
    fn generate<'b>(&'b self, sw: &'b mut impl SliceWriter) {
        let bytes = self.packet.encode();
        tracing::debug!("Bytes before encrypt = {:X?}", bytes);

        let mut bytes: Vec<u8> = bytes.to_vec();

        while !bytes.len().is_multiple_of(16) {
            bytes.push(0);
        }

        if let Some(keyv) = &self.encryption_key {
            let mut key: [u8; 16] = [0u8; 16];
            key.copy_from_slice(keyv);

            let iv = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            let cipher = Aes128CbcEnc::new(&key.into(), &iv.into());

            let l = bytes.len();
            let encrypted = cipher.encrypt_padded_mut::<NoPadding>(&mut bytes, l).unwrap();
            bytes = encrypted.to_vec();
        }

        let first_word: u32 = ((bytes[0] as u32) << 24)
            | ((bytes[1] as u32) << 16)
            | ((bytes[2] as u32) << 8)
            | (bytes[3] as u32);
        let second_word: u32 = ((bytes[4] as u32) << 24)
            | ((bytes[5] as u32) << 16)
            | ((bytes[6] as u32) << 8)
            | (bytes[7] as u32);

        let scrambled_session_id = (self.session_id) ^ (first_word ^ second_word);

        sw.be_u32(scrambled_session_id);
        sw.put(bytes.as_slice());
    }
}
impl Multiplex {
    pub fn decode<'a>(i: &'a [u8], decryption_key: &[u8]) -> nom::IResult<&'a [u8], Self> {
        let (i, scrambled_session_id) = nom::number::complete::be_u32(i)?;

        let first_word: u32 =
            ((i[0] as u32) << 24) | ((i[1] as u32) << 16) | ((i[2] as u32) << 8) | (i[3] as u32);
        let second_word: u32 =
            ((i[4] as u32) << 24) | ((i[5] as u32) << 16) | ((i[6] as u32) << 8) | (i[7] as u32);

        let session_id = scrambled_session_id ^ (first_word ^ second_word);

        let mut mut_i = i.to_vec();

        // i must be decrypted

        let mut key: [u8; 16] = [0u8; 16];
        key.copy_from_slice(decryption_key);

        let iv = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let cipher = Aes128CbcDec::new(&key.into(), &iv.into());
        let decrypted = cipher.decrypt_padded_mut::<NoPadding>(&mut mut_i).unwrap().to_vec();

        tracing::debug!("Decrypted packet = {:X?}", decrypted);

        let (_, flash_packet) = FlashProfilePlainPacket::decode(&decrypted).unwrap();

        Ok((
            i,
            Self {
                packet: flash_packet,
                session_id,
                encryption_key: None,
            },
        ))
    }
}

#[cfg(test)]
pub mod test {
    use crate::endpoint_discriminator::{AncillaryDataBody, EndpointDiscriminator};
    use crate::multiplex::Multiplex;
    use crate::packet_flags::{PacketFlag, PacketFlags, PacketMode};
    use parse::{GenerateBytes, SliceWriter, VecSliceWriter};
    use crate::flash_profile_plain_packet::FlashProfilePlainPacket;
    use crate::IHelloChunkBody;
    use crate::packet::Packet;

    #[test]
    #[ignore]
    pub fn multiplex_round_trip() {
        let mut m = Multiplex {
            session_id: 0,
            packet: FlashProfilePlainPacket {
                session_sequence_number: 0,
                checksum: 59579,
                packet: Packet {
                    flags: PacketFlags::new(
                        PacketMode::Startup,
                        PacketFlag::TimestampPresent.into(),
                    ),
                    timestamp: Some(0),
                    timestamp_echo: None,
                    chunks: vec![IHelloChunkBody {
                        epd_length: 2.into(),
                        endpoint_discriminator: EndpointDiscriminator(vec![AncillaryDataBody {
                            ancillary_data: Vec::new(),
                        }
                            .into()]),
                        tag: vec![0u8; 16],
                    }
                        .into()],
                },
            },
            encryption_key: None,
        };

        let mut sw = VecSliceWriter::default();
        m.encryption_key = Some(b"Adobe Systems 02".to_vec());
        m.generate(&mut sw);

        let (i, dec) = Multiplex::decode(sw.as_slice(), b"Adobe Systems 02").unwrap();

        println!("{:#?}", m);
        println!("{:#?}", dec);

        assert_eq!(dec, m);
        assert_eq!(i, &[]);
    }
}