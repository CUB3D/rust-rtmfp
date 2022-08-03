use std::env::args;
use enumset::EnumSet;
use hmac_sha256::HMAC;
use std::ffi::{c_int, c_void};
use std::thread::sleep;
use std::time::Duration;

use nom::AsBytes;
use num_bigint::BigUint;
use num_traits::Num;
use openssl::bn::BigNum;
use rand::{thread_rng, Rng};
use rtmfp::chunk_ping::PingBody;
use rtmfp::chunk_session_close_acknowledgement::SessionCloseAcknowledgementBody;
use rtmfp::chunk_user_data::{
    UserDataChunk, UserDataChunkFlags, UserDataChunkFragmentControl, UserDataChunkOptionType,
};
use rtmfp::encode::StaticEncode;
use rtmfp::endpoint_discriminator::AncillaryDataBody;
use rtmfp::flash_certificate::{get_extra_randomness, FlashCertificate};
use rtmfp::flash_profile_plain_packet::FlashProfilePlainPacket;
use rtmfp::packet::{PacketFlag, PacketFlags, PacketMode};
use rtmfp::rtmfp_option::RTMFPOption;
use rtmfp::rtmfp_stream::RTMFPStream;
use rtmfp::session_key_components::{
    get_epehemeral_diffie_hellman_public_key, EphemeralDiffieHellmanPublicKeyBody,
    ExtraRandomnessBody,
};
use rtmfp::{ChunkContent, IHelloChunkBody, IIKeyingChunkBody, Multiplex, Packet, PingReplyBody};

mod tui_ {
    use std::time::Duration;
    use crossterm::event::{Event, KeyCode, KeyEvent};
    use tui::backend::CrosstermBackend;
    use tui::layout::{Constraint, Direction, Layout};
    use tui::Terminal;
    use tui::widgets::{Block, Borders, Paragraph};

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

        crossterm::terminal::disable_raw_mode()?;

        Ok(())
    }
}

fn main() -> std::io::Result<()> {
    if args().last().unwrap() == "tui" {
        return tui_::do_tui();
    }

    let mut stream = RTMFPStream::new_client();

    let mut our_tag = [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
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

    println!("Wait for stage 2");

    // They send back Tag, Cookie and RCert
    let (m2, srv) = stream.read().expect("m2");

    let rec_body = m2
        .packet
        .packet
        .chunks
        .first()
        .unwrap()
        .payload
        .get_rhello()
        .unwrap();

    let keypair = sussy_hellman::KeyPair::generate(sussy_hellman::KeyPairParams::new_flash());
    let pub_key_hex = keypair.public.to_str_radix(16);
    let openssl_bn_pub_key = BigNum::from_hex_str(&pub_key_hex).unwrap();
    let public_key_bytes = openssl_bn_pub_key.to_vec();

    let our_nonce = b"ABAB";

    // skic must only have a ephemeral public key and extra randomness, cert must be empty
    let mut body = IIKeyingChunkBody::new(
        0x69,
        rec_body.cookie,
        FlashCertificate {
            cannonical: vec![],
            remainder: vec![],
        },
        vec![
            EphemeralDiffieHellmanPublicKeyBody {
                group_id: 2.into(),
                public_key: public_key_bytes.clone(),
            }
                .into(),
            ExtraRandomnessBody {
                extra_randomness: our_nonce.to_vec(),
            }
                .into(),
        ],
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
    };

    stream.send(m, srv);

    println!("Waiting for stage 4");

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

    let their_key_bn = BigNum::from_slice(&their_key_bytes).unwrap();
    let their_key_hex = their_key_bn.to_hex_str().unwrap().to_owned();
    let bignum_key = BigUint::from_str_radix(&their_key_hex, 16).unwrap();
    let shared_key = keypair.compute_key(&bignum_key);
    let shared_key_hex = shared_key.to_str_radix(16);
    let shared_key_openssl = BigNum::from_hex_str(&shared_key_hex).unwrap();
    let shared_key_bytes = shared_key_openssl.to_vec();

    println!("Secret hex = {}", shared_key_hex);
    println!("Init nonce = {:?}", our_nonce);

    let their_nonce = stage_4
        .packet
        .packet
        .chunks
        .first()
        .unwrap()
        .payload
        .get_rikeying()
        .unwrap()
        .session_key_responder_component
        .encode_static();

    println!(
        "Server nonce (size = {}) = {:X?}",
        their_nonce.len(),
        their_nonce
    );

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
                        value: vec![],
                    }],
                    user_data: vec![],
                }
                    .into()],
            },
        },
    };
    stream.send(flow_start_packet, srv);

    let (res, srv) = stream.read().unwrap();

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
    };
    stream.send(ping, srv);

    let mut buffer = Vec::new();

    loop {
        let mut buf = [0; 8192];

        if let Ok((amt, src)) = stream.socket.recv_from(&mut buf) {
            // Crop the buffer to the size of the packet
            let buf = &buf[..amt];

            buffer.extend_from_slice(&buf);

            println!("Got bytes = {:?}", buf);
        }

        if let Ok((i, packet)) = Multiplex::decode(&buffer, &stream.decryption_key) {
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
            };
            stream.send(ping, srv);

            sleep(Duration::from_micros(100));
        }
    }

    Ok(())
}
