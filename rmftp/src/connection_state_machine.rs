use crate::ChunkContent;

struct ConnectionState<T> {
    data: T,
}
impl<T: Default> Default for ConnectionState<T> {
    fn default() -> Self {
        Self { data: T::default() }
    }
}

impl From<ConnectionState<SIHelloSent>> for ConnectionState<SOpen> {
    fn from(_: ConnectionState<SIHelloSent>) -> Self {
        todo!()
    }
}
impl From<ConnectionState<SIHelloSent>> for ConnectionState<SOpenFailed> {
    fn from(_: ConnectionState<SIHelloSent>) -> Self {
        todo!()
    }
}

#[derive(Default)]
struct SIHelloSent;
#[derive(Default)]
struct SOpen;
#[derive(Default)]
struct SOpenFailed;
#[derive(Default)]
struct SKeyingSent;
#[derive(Default)]
struct SNearClose;
#[derive(Default)]
struct SFarCloseLinger;
#[derive(Default)]
struct SClose;

enum ConnectionStateWrapper {
    IHelloSent(ConnectionState<SIHelloSent>),
    KeyingSent(ConnectionState<SKeyingSent>),
    SOpen(ConnectionState<SOpen>),
}

impl ConnectionStateWrapper {
    fn process_chunk_body(&self, cc: ChunkContent) {
        let new_state = match (self, cc) {
            (ConnectionStateWrapper::IHelloSent(_cs), ChunkContent::RHello(_)) => {
                ConnectionStateWrapper::KeyingSent(ConnectionState::<SKeyingSent>::default())
            }
            _ => panic!(),
        };
    }
}
