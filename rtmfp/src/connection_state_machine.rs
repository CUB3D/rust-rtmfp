use std::marker::PhantomData;
use crate::{ChunkContent, IIKeyingChunkBody, RHelloChunkBody};
use crate::chunk_rikeying::ResponderInitialKeyingChunkBody;
// struct ConnectionState<T> {
//     data: PhantomData<T>,
// }
// impl<T: Default> Default for ConnectionState<T> {
//     fn default() -> Self {
//         Self { data: Default::default() }
//     }
// }
// 
// impl From<ConnectionState<SIHelloSent>> for ConnectionState<SOpen> {
//     fn from(_: ConnectionState<SIHelloSent>) -> Self {
//         todo!()
//     }
// }
// impl From<ConnectionState<SIHelloSent>> for ConnectionState<SOpenFailed> {
//     fn from(_: ConnectionState<SIHelloSent>) -> Self {
//         todo!()
//     }
// }

// #[derive(Default)]
// struct SIHelloSent;
// #[derive(Default)]
// struct SOpen;
// #[derive(Default)]
// struct SOpenFailed;
// #[derive(Default)]
// struct SKeyingSent;
// #[derive(Default)]
// struct SNearClose;
// #[derive(Default)]
// struct SFarCloseLinger;
// #[derive(Default)]
// struct SClose;

pub enum ConnectionEvent {
    SentIHello,
    ReceivedRHello(RHelloChunkBody),
    SentIIKeying,
    ReceivedRIKeying(ResponderInitialKeyingChunkBody),
    HandshakeComplete,
}

#[derive(Debug, Clone)]
pub enum ConnectionStateWrapper {
    Init,
    IHelloSent,
    RHelloRecv(RHelloChunkBody),
    IIKeyingSent,
    RIKeyingRecv(ResponderInitialKeyingChunkBody),
    HandshakeComplete,
}

impl ConnectionStateWrapper {
    pub fn new() -> Self {
        Self::Init
    }
    
    pub fn transition(&mut self, event: ConnectionEvent) {
        match (self.clone(), event) {
            (ConnectionStateWrapper::Init, ConnectionEvent::SentIHello) => {
                *self = ConnectionStateWrapper::IHelloSent;
            }
            (ConnectionStateWrapper::IHelloSent, ConnectionEvent::ReceivedRHello(r)) => {
                *self = ConnectionStateWrapper::RHelloRecv(r);
            }
            (ConnectionStateWrapper::RHelloRecv(_), ConnectionEvent::SentIIKeying) => {
                *self = ConnectionStateWrapper::IIKeyingSent;
            }
            (ConnectionStateWrapper::IIKeyingSent, ConnectionEvent::ReceivedRIKeying(r)) => {
                *self = ConnectionStateWrapper::RIKeyingRecv(r);
            }
            (ConnectionStateWrapper::RIKeyingRecv(_), ConnectionEvent::HandshakeComplete) => {
                *self = ConnectionStateWrapper::HandshakeComplete;
            }
            _ => {}
        }
    }
    
    fn process_chunk_body(&self, cc: ChunkContent) {
        let _new_state = match (self, cc) {
            // (ConnectionStateWrapper::IHelloSent(_cs), ChunkContent::RHello(_)) => {
            //     ConnectionStateWrapper::KeyingSent(ConnectionState::<SKeyingSent>::default())
            // }
            _ => panic!(),
        };
    }
}
