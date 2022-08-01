use crate::Multiplex;
use cookie_factory::gen;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

pub struct RTMFPStream {
    socket: UdpSocket,
    encryption_key: Option<Vec<u8>>,
    decryption_key: Vec<u8>,
}

impl RTMFPStream {
    pub fn new_server() -> Self {
        let socket = UdpSocket::bind("127.0.0.1:1935").unwrap();

        Self {
            socket,
            encryption_key: Some(b"Adobe Systems 02".to_vec()),
            decryption_key: b"Adobe Systems 02".to_vec(),
        }
    }

    pub fn new_client() -> Self {
        let socket = UdpSocket::bind("127.0.0.1:20202").unwrap();

        socket.connect("127.0.0.1:1935").unwrap();

        Self {
            socket,
            encryption_key: Some(b"Adobe Systems 02".to_vec()),
            decryption_key: b"Adobe Systems 02".to_vec(),
        }
    }

    pub fn send(&self, m: Multiplex, dest: SocketAddr) {
        let v = vec![];
        let (bytes, _s2) = gen(m.encode(&self.encryption_key), v).unwrap();
        println!("Send = {:?}", bytes);
        // self.socket.send_to(&bytes, dest).unwrap();
        self.socket.send(&bytes).unwrap();
    }

    pub fn read(&self) -> Option<(Multiplex, SocketAddr)> {
        let mut buf = [0; 1024];

        if let Ok((amt, src)) = self.socket.recv_from(&mut buf) {
            // Crop the buffer to the size of the packet
            let buf = &buf[..amt];
            let (_i, m) = Multiplex::decode(buf, &self.decryption_key).unwrap();
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
