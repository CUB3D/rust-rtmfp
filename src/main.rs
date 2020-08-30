use cookie_factory::bytes::{be_u32, be_u8, be_u16};
use cookie_factory::sequence::tuple;
use std::net::UdpSocket;
use cookie_factory::gen;

fn main() -> std::io::Result<()> {
    {
        let mut socket = UdpSocket::bind("127.0.0.1:2020")?;

        socket.connect("127.0.0.1:1935").unwrap();

        let first_word = (3 << 24) | (0x30 << 16) | (0 << 8) | (65 << 0);
        let second_word = (65 << 24) | (65 << 16) | (65 << 8) | (65 << 0);

        // Scramble the sid
        let sid = 0 ^ (first_word ^ second_word);
        print!("sid {}", sid);

        let v = vec![];
        let (bytes, size) = gen(
            tuple((
                // Sid
                be_u32(sid),
                // flags (include mode)
                be_u8(3),
                // chunk id
                be_u8(0x30), // 48
                // total size of chunk
                be_u16(7),
                // size of descriptor (EP thing)
                be_u8(3),
                be_u8(65),
                be_u8(65),
                be_u8(65),
                // Rest is the string ( total size - size of descriptor)
                be_u8(65),
                be_u8(65),
                be_u8(65),
            )),
            v
        ).unwrap();

        socket.send(&bytes).unwrap();

        // Receives a single datagram message on the socket. If `buf` is too small to hold
        // the message, it will be cut off.
        // let mut buf = [0; 10];
        // let (amt, src) = socket.recv_from(&mut buf)?;

        // Redeclare `buf` as slice of the received data and send reverse data back to origin.
        // let buf = &mut buf[..amt];
        // buf.reverse();
        // socket.send_to(buf, &src)?;
    } // the socket is closed here
    Ok(())
}
