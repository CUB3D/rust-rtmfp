use enumset::EnumSet;
use std::env::args;
use std::thread::sleep;
use std::time::Duration;

use nom::AsBytes;
use num_bigint::BigUint;
use num_traits::Num;
use openssl::bn::BigNum;
use rtmfp::chunk_ping::PingBody;
use rtmfp::chunk_user_data::{
    UserDataChunk, UserDataChunkFlags, UserDataChunkFragmentControl, UserDataChunkOptionType,
};
use rtmfp::encode::StaticEncode;
use rtmfp::endpoint_discriminator::{AncillaryDataBody, EndpointDiscriminator};
use rtmfp::flash_certificate::FlashCertificate;
use rtmfp::flash_profile_plain_packet::FlashProfilePlainPacket;
use rtmfp::packet_flags::{PacketFlag, PacketFlags, PacketMode};
use rtmfp::rtmfp_option::RTMFPOption;
use rtmfp::rtmfp_stream::RTMFPStream;
use rtmfp::session_key_components::{get_ephemeral_diffie_hellman_public_key, EphemeralDiffieHellmanPublicKeyBody, ExtraRandomnessBody, SessionKeyingComponent};
use rtmfp::{IHelloChunkBody, IIKeyingChunkBody};
use rtmfp::connection_state_machine::{ConnectionEvent, ConnectionStateWrapper};
use rtmfp::multiplex::Multiplex;
use rtmfp::packet::Packet;

mod tui_ {
    use crossterm::event::{Event, KeyCode};
    use std::time::Duration;
    use tui::backend::CrosstermBackend;
    use tui::layout::{Constraint, Direction, Layout};
    use tui::widgets::{Block, Borders, Paragraph};
    use tui::Terminal;

    pub fn do_tui() -> Result<(), std::io::Error> {
        let stdout = std::io::stdout();
        crossterm::terminal::enable_raw_mode()?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;
        terminal.clear().unwrap();

        let mut command = String::from("asdf");

        loop {
            terminal.draw(|f| {
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .margin(1)
                    .constraints(
                        [
                            Constraint::Percentage(10),
                            Constraint::Percentage(80),
                            Constraint::Percentage(10)
                        ].as_ref()
                    )
                    .split(f.size());

                let block = Block::default()
                    .title("Block")
                    .borders(Borders::ALL);

                let para = Paragraph::new(command.clone())
                    .block(block);

                f.render_widget(para, chunks[0]);
                let block = Block::default()
                    .title("Block 2")
                    .borders(Borders::ALL);
                f.render_widget(block, chunks[1]);
            })?;

            if crossterm::event::poll(Duration::from_micros(1))? {
                if let Event::Key(key) = crossterm::event::read()? {
                    match key.code {
                        KeyCode::Char(c) => {
                            command.push(c);
                        }
                        _ => {},
                    }
                }
            }
        }

        // crossterm::terminal::disable_raw_mode()?;

        // Ok(())
    }
}

fn main() -> std::io::Result<()> {
    use tracing_subscriber::EnvFilter;

    tracing_subscriber::fmt::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    if args().next_back().unwrap() == "tui" {
        return tui_::do_tui();
    }

    let mut stream = RTMFPStream::connect("127.0.0.1:20202", "127.0.0.1:1935")?;

    let mut state_machine = ConnectionStateWrapper::new();

    let our_nonce = b"ABAB";
    let mut responder_session_id = 0u32;
    let keypair = sussy_hellman::KeyPair::generate(sussy_hellman::KeyPairParams::new_flash());


    loop {
        println!("Cur state {:?}", &state_machine);
        match state_machine {
            ConnectionStateWrapper::Init => {
                let our_tag = [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
                //thread_rng().fill(&mut our_tag);
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
                                endpoint_discriminator: EndpointDiscriminator(vec![AncillaryDataBody {
                                    ancillary_data: Vec::new(),
                                }
                                    .into()]),
                                tag: our_tag.to_vec(),
                            }
                                .into()],
                        },
                    },
                    encryption_key: None,
                };

                stream.send(m);
                state_machine.transition(ConnectionEvent::SentIHello);
            }
            ConnectionStateWrapper::IHelloSent => {
                //TOOD: handle other pkt types
                let (m2, _srv) = stream.read().expect("m2");

                println!("{:?}", m2);

                let rec_body = m2
                    .packet
                    .packet
                    .chunks
                    .first()
                    .unwrap()
                    .payload
                    .get_rhello()
                    .unwrap();
                state_machine.transition(ConnectionEvent::ReceivedRHello(rec_body));
            }
            ConnectionStateWrapper::RHelloRecv(ref rec_body) => {
                let pub_key_hex = keypair.public.to_str_radix(16);
                let openssl_bn_pub_key = BigNum::from_hex_str(&pub_key_hex).unwrap();
                let public_key_bytes = openssl_bn_pub_key.to_vec();


                // skic must only have a ephemeral public key and extra randomness, cert must be empty
                let mut body = IIKeyingChunkBody::new(
                    0x69,
                    rec_body.cookie.clone(),
                    FlashCertificate {
                        canonical: Vec::new(),
                        remainder: Vec::new(),
                    },
                    SessionKeyingComponent(vec![
                        EphemeralDiffieHellmanPublicKeyBody {
                            group_id: 2.into(),
                            public_key: public_key_bytes.clone(),
                        }
                            .into(),
                        ExtraRandomnessBody {
                            extra_randomness: our_nonce.to_vec(),
                        }
                            .into(),
                    ]),
                );
                body.signature = public_key_bytes.clone();
                body.nonce = our_nonce.to_vec();

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
                            chunks: vec![body.into()],
                        },
                    },
                    encryption_key: None,
                };

                stream.send(m);
                state_machine.transition(ConnectionEvent::SentIIKeying);
            }
            ConnectionStateWrapper::IIKeyingSent => {
                println!("Waiting for stage 4");

                let (stage_4, _srv) = stream.read().unwrap();

                println!("Got stage4: {:?}", stage_4);

                let rkey = stage_4
                    .packet
                    .packet
                    .chunks
                    .first()
                    .unwrap()
                    .payload
                    .get_rikeying()
                    .unwrap();
                state_machine.transition(ConnectionEvent::ReceivedRIKeying(rkey));
            }
            ConnectionStateWrapper::RIKeyingRecv(ref rkey) => {
                let their_key_bytes = get_ephemeral_diffie_hellman_public_key(
                    rkey
                        .session_key_responder_component.0.clone(),
                )
                    .unwrap()
                    .public_key;

                //TODO: dedupe
                let their_key_bn = BigNum::from_slice(&their_key_bytes).unwrap();
                let their_key_hex = their_key_bn.to_hex_str().unwrap().to_owned();
                let bignum_key = BigUint::from_str_radix(&their_key_hex, 16).unwrap();
                let shared_key = keypair.compute_key(&bignum_key);
                let shared_key_hex = shared_key.to_str_radix(16);
                let shared_key_openssl = BigNum::from_hex_str(&shared_key_hex).unwrap();
                let shared_key_bytes = shared_key_openssl.to_vec();

                println!("Secret hex = {}", shared_key_hex);
                // println!("Init nonce = {:?}", our_nonce);

                let their_nonce = rkey
                    .session_key_responder_component
                    .encode_static();

                println!(
                    "Server nonce (size = {}) = {:X?}",
                    their_nonce.len(),
                    their_nonce
                );

                responder_session_id = rkey
                    .responder_session_id;

                // Compute packet keys
                let encrypt_key = &hmac_sha256::HMAC::mac(
                    hmac_sha256::HMAC::mac(their_nonce.as_bytes(), our_nonce.as_bytes()).as_bytes(),
                    &shared_key_bytes,
                );
                let decrypt_key = &hmac_sha256::HMAC::mac(
                    hmac_sha256::HMAC::mac(our_nonce.as_bytes(), their_nonce.as_bytes()).as_bytes(),
                    &shared_key_bytes,
                );
                println!("Got enc key: {:?}", encrypt_key);
                println!("Got dec key: {:?}", decrypt_key);

                stream.set_encrypt_key(decrypt_key[..16].to_vec());
                stream.set_decrypt_key(encrypt_key[..16].to_vec());

                println!("Handshake done\n\n\n");
                stream.set_timeout();
                state_machine.transition(ConnectionEvent::HandshakeComplete);
            }
            ConnectionStateWrapper::HandshakeComplete => {
               break;
            }
        }
    }

    // let our_tag = [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    // //thread_rng().fill(&mut our_tag);
    // let m = Multiplex {
    //     session_id: 0,
    //     packet: FlashProfilePlainPacket {
    //         session_sequence_number: 0,
    //         checksum: 0,
    //         packet: Packet {
    //             flags: PacketFlags::new(
    //                 PacketMode::Startup,
    //                 PacketFlag::TimestampPresent.into(),
    //             ),
    //             timestamp: Some(0),
    //             timestamp_echo: None,
    //             chunks: vec![IHelloChunkBody {
    //                 epd_length: 2.into(),
    //                 endpoint_discriminator: EndpointDiscriminator(vec![AncillaryDataBody {
    //                     ancillary_data: Vec::new(),
    //                 }
    //                     .into()]),
    //                 tag: our_tag.to_vec(),
    //             }
    //                 .into()],
    //         },
    //     },
    //     encryption_key: None,
    // };
    //
    // stream.send(m);
    //
    // println!("Wait for stage 2");
    //
    // // They send back Tag, Cookie and RCert
    // let (m2, _srv) = stream.read().expect("m2");
    //
    // let rec_body = m2
    //     .packet
    //     .packet
    //     .chunks
    //     .first()
    //     .unwrap()
    //     .payload
    //     .get_rhello()
    //     .unwrap();
    //
    // let keypair = sussy_hellman::KeyPair::generate(sussy_hellman::KeyPairParams::new_flash());
    // let pub_key_hex = keypair.public.to_str_radix(16);
    // let openssl_bn_pub_key = BigNum::from_hex_str(&pub_key_hex).unwrap();
    // let public_key_bytes = openssl_bn_pub_key.to_vec();
    //
    // let our_nonce = b"ABAB";
    //
    // // skic must only have a ephemeral public key and extra randomness, cert must be empty
    // let mut body = IIKeyingChunkBody::new(
    //     0x69,
    //     rec_body.cookie,
    //     FlashCertificate {
    //         canonical: Vec::new(),
    //         remainder: Vec::new(),
    //     },
    //     SessionKeyingComponent(vec![
    //         EphemeralDiffieHellmanPublicKeyBody {
    //             group_id: 2.into(),
    //             public_key: public_key_bytes.clone(),
    //         }
    //             .into(),
    //         ExtraRandomnessBody {
    //             extra_randomness: our_nonce.to_vec(),
    //         }
    //             .into(),
    //     ]),
    // );
    // body.signature = public_key_bytes.clone();
    // body.nonce = our_nonce.to_vec();
    //
    // let m = Multiplex {
    //     session_id: 0,
    //     packet: FlashProfilePlainPacket {
    //         session_sequence_number: 0,
    //         checksum: 0,
    //         packet: Packet {
    //             flags: PacketFlags::new(
    //                 PacketMode::Startup,
    //                 PacketFlag::TimestampPresent.into(),
    //             ),
    //             timestamp: Some(0),
    //             timestamp_echo: None,
    //             chunks: vec![body.into()],
    //         },
    //     },
    //     encryption_key: None,
    // };
    //
    // stream.send(m);
    //
    // println!("Waiting for stage 4");
    //
    // let (stage_4, _srv) = stream.read().unwrap();
    //
    // println!("Got stage4: {:?}", stage_4);
    //
    // let their_key_bytes = get_ephemeral_diffie_hellman_public_key(
    //     stage_4
    //         .packet
    //         .packet
    //         .chunks
    //         .first()
    //         .unwrap()
    //         .payload
    //         .get_rikeying()
    //         .unwrap()
    //         .session_key_responder_component.0,
    // )
    //     .unwrap()
    //     .public_key;
    //
    // let their_key_bn = BigNum::from_slice(&their_key_bytes).unwrap();
    // let their_key_hex = their_key_bn.to_hex_str().unwrap().to_owned();
    // let bignum_key = BigUint::from_str_radix(&their_key_hex, 16).unwrap();
    // let shared_key = keypair.compute_key(&bignum_key);
    // let shared_key_hex = shared_key.to_str_radix(16);
    // let shared_key_openssl = BigNum::from_hex_str(&shared_key_hex).unwrap();
    // let shared_key_bytes = shared_key_openssl.to_vec();
    //
    // println!("Secret hex = {}", shared_key_hex);
    // println!("Init nonce = {:?}", our_nonce);
    //
    // let their_nonce = stage_4
    //     .packet
    //     .packet
    //     .chunks
    //     .first()
    //     .unwrap()
    //     .payload
    //     .get_rikeying()
    //     .unwrap()
    //     .session_key_responder_component
    //     .encode_static();
    //
    // println!(
    //     "Server nonce (size = {}) = {:X?}",
    //     their_nonce.len(),
    //     their_nonce
    // );
    //
    // let responder_session_id = stage_4
    //     .clone()
    //     .packet
    //     .packet
    //     .chunks
    //     .first()
    //     .unwrap()
    //     .payload
    //     .get_rikeying()
    //     .unwrap()
    //     .responder_session_id;
    //
    // // Compute packet keys
    // let encrypt_key = &hmac_sha256::HMAC::mac(
    //     hmac_sha256::HMAC::mac(their_nonce.as_bytes(), our_nonce.as_bytes()).as_bytes(),
    //     &shared_key_bytes,
    // );
    // let decrypt_key = &hmac_sha256::HMAC::mac(
    //     hmac_sha256::HMAC::mac(our_nonce.as_bytes(), their_nonce.as_bytes()).as_bytes(),
    //     &shared_key_bytes,
    // );
    // println!("Got enc key: {:?}", encrypt_key);
    // println!("Got dec key: {:?}", decrypt_key);
    //
    // stream.set_encrypt_key(decrypt_key[..16].to_vec());
    // stream.set_decrypt_key(encrypt_key[..16].to_vec());
    //
    // println!("Handshake done\n\n\n");
    // stream.set_timeout();

    let flow_start_packet = Multiplex {
        session_id: responder_session_id,
        packet: FlashProfilePlainPacket {
            session_sequence_number: 1,
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
                        value: Vec::new(),
                    }],
                    user_data: Vec::new(),
                }
                    .into()],
            },
        },
        encryption_key: None,
    };
    stream.send(flow_start_packet);

    let (res, _srv) = stream.read().unwrap();

    println!("res = {:?}", res);

    stream.set_timeout();

    let ping = Multiplex {
        session_id: responder_session_id,
        packet: FlashProfilePlainPacket {
            session_sequence_number: 0,
            checksum: 0,
            packet: Packet {
                flags: PacketFlags::new(
                    PacketMode::Initiator,
                    PacketFlag::TimestampPresent.into(),
                ),
                timestamp: Some(123),
                timestamp_echo: None,
                chunks: vec![PingBody {
                    message: b"Hello".as_bytes().to_vec(),
                }
                    .into()],
            },
        },
        encryption_key: None,
    };
    stream.send(ping);

    let mut buffer = Vec::new();

    loop {
        let mut buf = [0; 8192];

        if let Ok((amt, _src)) = stream.socket.recv_from(&mut buf) {
            // Crop the buffer to the size of the packet
            let buf = &buf[..amt];

            buffer.extend_from_slice(buf);

            tracing::debug!("Got bytes = {:?}", buf);
        }

        if let Ok((_i, packet)) = Multiplex::decode(&buffer, &stream.decryption_key) {
            println!("Got new packet {:?}", packet);
            // buffer = i.to_vec();
            buffer.clear();

            /*let chunks = packet.packet.packet.chunks;

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
                }*/

            let ping = Multiplex {
                session_id: responder_session_id,
                packet: FlashProfilePlainPacket {
                    session_sequence_number: 0,
                    checksum: 0,
                    packet: Packet {
                        flags: PacketFlags::new(
                            PacketMode::Initiator,
                            PacketFlag::TimestampPresent.into(),
                        ),
                        timestamp: Some(123),
                        timestamp_echo: None,
                        chunks: vec![PingBody {
                            message: b"Hello".as_bytes().to_vec(),
                        }
                            .into()],
                    },
                },
                encryption_key: None,
            };
            stream.send(ping);

            sleep(Duration::from_micros(100));
        }
    }

    // Ok(())
}
