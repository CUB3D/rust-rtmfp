use std::io;
use parse::{GenerateBytes, SliceWriter, VecSliceWriter};
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::Duration;
use crate::multiplex::Multiplex;

const DEFAULT_ENCRYPTION_KEY: &'static [u8] = b"Adobe Systems 02";

pub struct RTMFPStream {
    pub socket: UdpSocket,
    //TODO: vec?
    encryption_key: Option<Vec<u8>>,
    //TODO: pub
    pub decryption_key: Vec<u8>,
}

impl RTMFPStream {
    pub fn new_server<A: ToSocketAddrs>(host: A) -> io::Result<Self> {
        let socket = UdpSocket::bind(host)?;

        Ok(Self {
            socket,
            encryption_key: Some(DEFAULT_ENCRYPTION_KEY.to_vec()),
            decryption_key: DEFAULT_ENCRYPTION_KEY.to_vec(),
        })
    }

    pub fn connect<A: ToSocketAddrs>(local: A, srv: A) -> io::Result<Self> {
        let socket = UdpSocket::bind(local)?;

        socket.connect(srv)?;

        Ok(Self {
            socket,
            encryption_key: Some(DEFAULT_ENCRYPTION_KEY.to_vec()),
            decryption_key: DEFAULT_ENCRYPTION_KEY.to_vec(),
        })
    }

    pub fn send(&self, mut m: Multiplex) {
        let mut sw = VecSliceWriter::default();
        m.encryption_key = self.encryption_key.clone();
        m.generate(&mut sw);
        println!("Send = {:X?}", sw.as_slice());
        self.socket.send(sw.as_slice()).unwrap();
    }

    pub fn read(&self) -> Option<(Multiplex, SocketAddr)> {
        let mut buf = [0; 8192];

        if let Ok((amt, src)) = self.socket.recv_from(&mut buf) {
            // Crop the buffer to the size of the packet
            let buf = &buf[..amt];
            let (_i, m) = Multiplex::decode(buf, &self.decryption_key).unwrap();
            println!("Remaining: {:X?}", _i);
            Some((m, src))
        } else {
            None
        }
    }

    pub fn set_timeout(&self) {
        self.socket
            .set_read_timeout(Some(Duration::from_millis(250)))
            .unwrap();
    }

    pub fn set_encrypt_key(&mut self, key: Vec<u8>) {
        self.encryption_key = Some(key)
    }

    pub fn set_decrypt_key(&mut self, key: Vec<u8>) {
        self.decryption_key = key
    }
}
