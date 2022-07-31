








use block_modes::{BlockMode};

use enumset::EnumSet;

use nom::{AsBytes};
use rand::{thread_rng, Rng};
use rtmfp::chunk_ping::PingBody;
use rtmfp::chunk_session_close_acknowledgement::SessionCloseAcknowledgementBody;
use rtmfp::chunk_user_data::{
    UserDataChunk, UserDataChunkFlags, UserDataChunkFragmentControl, UserDataChunkOptionType,
};
use rtmfp::endpoint_discriminator::AncillaryDataBody;
use rtmfp::flash_certificate::{get_extra_randomness, FlashCertificate};
use rtmfp::flash_profile_plain_packet::FlashProfilePlainPacket;
use rtmfp::keypair::KeyPair;
use rtmfp::packet::{PacketFlag, PacketFlags, PacketMode};
use rtmfp::rtmfp_option::RTMFPOption;
use rtmfp::session_key_components::{
    get_epehemeral_diffie_hellman_public_key, EphemeralDiffieHellmanPublicKeyBody,
    ExtraRandomnessBody,
};
use rtmfp::{ChunkContent, IHelloChunkBody, IIKeyingChunkBody, Multiplex, Packet, RTMFPStream};


fn main() -> std::io::Result<()> {
    {
        let mut stream = RTMFPStream::new_client();
        let encrypt_key = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let decrypt_key = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        stream.set_encrypt_key(encrypt_key.to_vec());
        stream.set_decrypt_key(decrypt_key.to_vec());

        let mut our_tag = [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        thread_rng().fill(&mut our_tag);

        let m = Multiplex {
            session_id: 0,
            packet: FlashProfilePlainPacket {
                session_sequence_number: 0,
                checksum: 0,
                packet: Packet {
                    flags: PacketFlags::new(
                        PacketMode::Startup,
                        PacketFlag::TimestampPresent.into(),
                    ),
                    timestamp: Some(0),
                    timestamp_echo: None,
                    chunks: vec![IHelloChunkBody {
                        epd_length: 2.into(),
                        endpoint_descriminator: vec![AncillaryDataBody {
                            ancillary_data: vec![],
                        }
                        .into()],
                        tag: our_tag.to_vec(),
                    }
                    .into()],
                },
            },
        };

        stream.send(m, "127.0.0.1:1935".parse().unwrap());

        let (m2, srv) = stream.read().unwrap();

        let their_nonce = get_extra_randomness(
            m2.clone()
                .packet
                .packet
                .chunks
                .first()
                .unwrap()
                .payload
                .get_rhello()
                .unwrap()
                .responder_certificate
                .cannonical,
        )
        .unwrap()
        .extra_randomness;

        println!("Got multiplex response: {:?}", m2);

        let rec_body = m2
            .packet
            .packet
            .chunks
            .first()
            .unwrap()
            .payload
            .get_rhello()
            .unwrap();

        let keypair = KeyPair::new();

        //TODO: sending wrong public key size here

        let our_nonce = b"AAAAAAAA".to_vec();

        // skic must only have a ephemeral public key and extra randomness, cert must be empty
        let m = Multiplex {
            session_id: 0,
            packet: FlashProfilePlainPacket {
                session_sequence_number: 0,
                checksum: 0,
                packet: Packet {
                    flags: PacketFlags::new(
                        PacketMode::Startup,
                        PacketFlag::TimestampPresent.into(),
                    ),
                    timestamp: Some(0),
                    timestamp_echo: None,
                    chunks: vec![IIKeyingChunkBody::new(
                        0,
                        rec_body.cookie,
                        FlashCertificate {
                            cannonical: vec![],
                            remainder: vec![],
                        },
                        vec![
                            EphemeralDiffieHellmanPublicKeyBody {
                                group_id: 2.into(),
                                public_key: keypair.public_key.clone(),
                            }
                            .into(),
                            ExtraRandomnessBody {
                                extra_randomness: our_nonce.clone(),
                            }
                            .into(),
                        ],
                    )
                    .into()],
                },
            },
        };

        stream.send(m, srv);

        let (stage_4, srv) = stream.read().unwrap();

        println!("Got stage4: {:?}", stage_4);

        let their_key_bytes = get_epehemeral_diffie_hellman_public_key(
            stage_4
                .packet
                .packet
                .chunks
                .first()
                .unwrap()
                .payload
                .get_rikeying()
                .unwrap()
                .session_key_responder_component,
        )
        .unwrap()
        .public_key;

        let responder_session_id = stage_4
            .clone()
            .packet
            .packet
            .chunks
            .first()
            .unwrap()
            .payload
            .get_rikeying()
            .unwrap()
            .responder_session_id;

        let shared_key = keypair.derive_shared_key(their_key_bytes);
        // Compute packet keys
        let _encrypt_key = &hmac_sha256::HMAC::mac(
            hmac_sha256::HMAC::mac(their_nonce.as_bytes(), our_nonce.as_bytes()).as_bytes(),
            &shared_key,
        )[..16];
        let _decrypt_key = &hmac_sha256::HMAC::mac(
            hmac_sha256::HMAC::mac(our_nonce.as_bytes(), their_nonce.as_bytes()).as_bytes(),
            &shared_key,
        )[..16];
        let encrypt_key = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let decrypt_key = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        stream.set_encrypt_key(encrypt_key.to_vec());
        stream.set_decrypt_key(decrypt_key.to_vec());

        println!("Handshake done\n\n\n");
        stream.set_timeout();

        let flow_start_packet = Multiplex {
            session_id: responder_session_id,
            packet: FlashProfilePlainPacket {
                session_sequence_number: 0,
                checksum: 0,
                packet: Packet {
                    flags: PacketFlags::new(
                        PacketMode::Initiator,
                        PacketFlag::TimestampPresent.into(),
                    ),
                    timestamp: Some(0),
                    timestamp_echo: None,
                    chunks: vec![UserDataChunk {
                        flags: UserDataChunkFlags {
                            flags: EnumSet::empty(),
                            fragment_control: UserDataChunkFragmentControl::Begin,
                        },
                        flow_id: 1.into(),
                        sequence_number: 1.into(),
                        forward_sequence_number_offset: 0.into(),
                        options: vec![RTMFPOption::Option {
                            type_: (UserDataChunkOptionType::PerFlowMetadata as u8).into(),
                            length: 0.into(),
                            value: vec![],
                        }],
                        user_data: vec![],
                    }
                    .into()],
                },
            },
        };
        stream.send(flow_start_packet, srv);

        loop {
            if let Some((packet, srv)) = stream.read() {
                println!("Got new packet {:?}", packet);

                let chunks = packet.packet.packet.chunks;

                for chunk in &chunks {
                    match chunk.payload {
                        ChunkContent::SessionCloseRequest(_) => {
                            let ack = Multiplex {
                                session_id: responder_session_id,
                                packet: FlashProfilePlainPacket {
                                    session_sequence_number: 0,
                                    checksum: 0,
                                    packet: Packet {
                                        flags: PacketFlags::new(
                                            PacketMode::Initiator,
                                            PacketFlag::TimestampPresent.into(),
                                        ),
                                        timestamp: Some(0),
                                        timestamp_echo: None,
                                        chunks: vec![SessionCloseAcknowledgementBody {}.into()],
                                    },
                                },
                            };
                            stream.send(ack, srv);
                        }
                        _ => {}
                    }
                }
            } else {
                println!("Timeout");

                let _m = Multiplex {
                    session_id: responder_session_id,
                    packet: FlashProfilePlainPacket {
                        session_sequence_number: 0,
                        checksum: 0,
                        packet: Packet {
                            flags: PacketFlags::new(
                                PacketMode::Initiator,
                                PacketFlag::TimestampPresent.into(),
                            ),
                            timestamp: Some(0),
                            timestamp_echo: None,
                            chunks: vec![PingBody {
                                message: "Hello".as_bytes().to_vec(),
                            }
                            .into()],
                        },
                    },
                };

                // stream.send(m);
            }
        }
    }
    Ok(())
}
