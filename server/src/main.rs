use rtmfp::chunk_rhello::RHelloChunkBody;
use rtmfp::chunk_rikeying::ResponderInitialKeyingChunkBody;
use rtmfp::flash_certificate::FlashCertificate;
use rtmfp::flash_profile_plain_packet::FlashProfilePlainPacket;
use rtmfp::packet::{PacketFlag, PacketFlags, PacketMode};
use rtmfp::ChunkContent::RIKeying;
use rtmfp::{ChunkContent, Multiplex, Packet, RTMFPStream};

fn main() {
    let stream = RTMFPStream::new_server();

    loop {
        if let Some((packet, src)) = stream.read() {
            println!("Got packet: {:?}", packet);

            let chunk = packet.packet.packet.chunks.first().unwrap();

            match &chunk.payload {
                ChunkContent::IHello(body) => {
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
                                chunks: vec![RHelloChunkBody {
                                    tag_length: body.clone().tag.len() as u8,
                                    tag_echo: body.clone().tag,
                                    cookie_length: 64.into(),
                                    cookie: vec![
                                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                    ],
                                    responder_certificate: FlashCertificate {
                                        cannonical: vec![],
                                        remainder: vec![],
                                    },
                                }
                                .into()],
                            },
                        },
                    };

                    stream.send(m, src);
                }
                ChunkContent::IIKeying(body) => {
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
                                chunks: vec![ResponderInitialKeyingChunkBody {
                                    responder_session_id: 1,
                                    skrc_length: 0.into(),
                                    session_key_responder_component: vec![],
                                    signature: vec![88],
                                }
                                .into()],
                            },
                        },
                    };

                    stream.send(m, src);
                }
                _ => {}
            }
        }
    }
}
