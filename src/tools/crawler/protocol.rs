use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Instant,
};

use futures_util::SinkExt;
use pea2pea::{
    protocols::{Handshake, Reading, Writing},
    Config, Connection, ConnectionSide, Node as Pea2PeaNode, Pea2Pea,
};
use tokio::time::{sleep, Duration};
use tokio_util::codec::Framed;
use tracing::*;
use ziggurat_zcash::{
    protocol::{
        message::Message,
        payload::{block::Headers, Addr, Version},
    },
    tools::synthetic_node::MessageCodec,
};

use super::network::KnownNetwork;
use crate::network::ConnectionState;

pub const NUM_CONN_ATTEMPTS_PERIODIC: usize = 500;
pub const MAX_CONCURRENT_CONNECTIONS: u16 = 1200;
pub const MAIN_LOOP_INTERVAL_SECS: u64 = 20;
pub const RECONNECT_INTERVAL_SECS: u64 = 5 * 60;
pub const MAX_WAIT_FOR_ADDR_SECS: u64 = 3 * 60;
pub const MAX_CONNECTION_FAILURES: u8 = 5;
pub const GETADDR_AFTER_VERSION_DELAY: Duration = Duration::from_secs(1);
pub const GETADDR_RETRY_DELAY: Duration = Duration::from_secs(8);
pub const MAX_GETADDR_PER_CONN: u8 = 2;

/// Represents the crawler together with network metrics it has collected.
#[derive(Clone)]
pub struct Crawler {
    node: Pea2PeaNode,
    pub known_network: Arc<KnownNetwork>,
    pub start_time: Instant,
    pub start_height: i32,
}

impl Pea2Pea for Crawler {
    fn node(&self) -> &Pea2PeaNode {
        &self.node
    }
}

impl Crawler {
    /// Creates a new instance of the `Crawler` without starting it.
    pub async fn new(start_height: i32) -> Self {
        let config = Config {
            name: Some("crawler".into()),
            listener_ip: None,
            max_connections: MAX_CONCURRENT_CONNECTIONS,
            ..Default::default()
        };

        Self {
            node: Pea2PeaNode::new(config),
            known_network: Default::default(),
            start_time: Instant::now(),
            start_height,
        }
    }

    /// Attempts to connect the crawler to the given address.
    pub async fn connect(&self, addr: SocketAddr) -> io::Result<()> {
        trace!(parent: self.node().span(), "attempting to connect to {}", addr);

        let timestamp = Instant::now();

        let result = self.node.connect(addr).await;

        if let Some(ref mut known_node) = self.known_network.nodes.write().get_mut(&addr) {
            match result {
                Ok(_) => {
                    known_node.connection_failures = 0;
                    known_node.last_connected = Some(timestamp);
                    known_node.handshake_time = Some(timestamp.elapsed());
                    known_node.state = ConnectionState::Connected;
                    known_node.getaddr_sent = 0;
                    known_node.received_addr = false;
                }
                Err(_) => {
                    trace!(parent: self.node().span(), "failed to connect to {}", addr);
                    known_node.connection_failures += 1;
                }
            }
        }

        result
    }

    /// Checks to see if crawler should connect to the given address.
    pub fn should_connect(&self, addr: SocketAddr) -> bool {
        if let Some(node) = self.known_network.nodes().get(&addr) {
            if node.connection_failures >= MAX_CONNECTION_FAILURES {
                return false;
            }

            if self.node().num_connected() + self.node().num_connecting()
                >= MAX_CONCURRENT_CONNECTIONS.into()
            {
                return false;
            }

            if self.node().is_connected(addr) || self.node().is_connecting(addr) {
                return false;
            }

            true
        } else {
            panic!("Logic bug! The crawler should only attempt to connect to known addresses.");
        }
    }

    async fn request_peers(&self, addr: SocketAddr) {
        let sent = self.known_network.bump_getaddr_sent(addr);
        if sent == 0 || sent > MAX_GETADDR_PER_CONN {
            return;
        }
        if let Ok(ok) = self.unicast(addr, Message::GetAddr) {
            let _ = ok.await;
        }
    }

    fn schedule_getaddr(&self, source: SocketAddr) {
        let crawler = self.clone();
        tokio::spawn(async move {
            sleep(GETADDR_AFTER_VERSION_DELAY).await;
            if !crawler.node().is_connected(source) {
                return;
            }
            if crawler
                .known_network
                .nodes()
                .get(&source)
                .map(|n| n.received_addr || n.getaddr_sent >= MAX_GETADDR_PER_CONN)
                .unwrap_or(true)
            {
                return;
            }
            crawler.request_peers(source).await;

            sleep(GETADDR_RETRY_DELAY).await;
            if !crawler.node().is_connected(source) {
                return;
            }
            if crawler
                .known_network
                .nodes()
                .get(&source)
                .map(|n| n.received_addr || n.getaddr_sent >= MAX_GETADDR_PER_CONN)
                .unwrap_or(true)
            {
                return;
            }
            crawler.request_peers(source).await;
        });
    }
}

#[async_trait::async_trait]
impl Handshake for Crawler {
    const TIMEOUT_MS: u64 = 2_000;

    async fn perform_handshake(&self, mut conn: Connection) -> io::Result<Connection> {
        let conn_addr = conn.addr();
        let own_listening_addr: SocketAddr = ([127, 0, 0, 1], 0).into();
        let mut framed_stream = Framed::new(self.borrow_stream(&mut conn), MessageCodec::default());

        let own_version = Message::Version(
            Version::new(conn_addr, own_listening_addr).with_start_height(self.start_height),
        );
        framed_stream.send(own_version).await?;

        Ok(conn)
    }
}

#[async_trait::async_trait]
impl Reading for Crawler {
    type Message = Message;
    type Codec = MessageCodec;

    fn codec(&self, _addr: SocketAddr, _side: ConnectionSide) -> Self::Codec {
        Default::default()
    }

    async fn process_message(&self, source: SocketAddr, message: Self::Message) -> io::Result<()> {
        match message {
            Message::Addr(addr) => {
                let listening_addrs: Vec<SocketAddr> = addr
                    .addrs
                    .iter()
                    .map(|a| a.addr)
                    .filter(|a| is_dialable(*a))
                    .collect();
                let len = listening_addrs.len();
                info!(parent: self.node().span(), "got {} address(es) from {}", len, source);

                self.known_network.add_addrs(source, &listening_addrs);
                self.known_network.mark_received_addr(source);

                if len > 1 || (len == 1 && listening_addrs[0] != source) {
                    self.node().disconnect(source).await;
                    self.known_network
                        .set_node_state(source, ConnectionState::Disconnected);
                }
            }
            Message::Ping(nonce) => {
                let _ = self.unicast(source, Message::Pong(nonce))?.await;
            }
            Message::GetAddr => {
                let _ = self.unicast(source, Message::Addr(Addr::empty()))?.await;
            }
            Message::GetHeaders(_) => {
                let _ = self
                    .unicast(source, Message::Headers(Headers::empty()))?
                    .await;
            }
            Message::GetData(inv) => {
                let _ = self.unicast(source, Message::NotFound(inv.clone()))?.await;
            }
            Message::Verack => {
                if self
                    .known_network
                    .nodes()
                    .get(&source)
                    .map(|n| n.getaddr_sent == 0 && !n.received_addr)
                    .unwrap_or(false)
                {
                    self.request_peers(source).await;
                }
            }
            Message::Version(ver) => {
                if let Some(known_node) = self.known_network.nodes.write().get_mut(&source) {
                    known_node.protocol_version = Some(ver.version);
                    known_node.user_agent = Some(ver.user_agent);
                    known_node.services = Some(ver.services);
                    known_node.start_height = Some(ver.start_height);
                }

                let _ = self.unicast(source, Message::Verack)?.await;
                let _ = self.unicast(source, Message::SendAddrV2)?.await;
                self.schedule_getaddr(source);
            }
            _ => {}
        }

        Ok(())
    }
}

impl Writing for Crawler {
    type Message = Message;
    type Codec = MessageCodec;

    fn codec(&self, _addr: SocketAddr, _side: ConnectionSide) -> Self::Codec {
        Default::default()
    }
}

fn is_dialable(addr: SocketAddr) -> bool {
    if addr.port() == 0 {
        return false;
    }
    match addr.ip() {
        IpAddr::V4(ip) => !(ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast()),
        IpAddr::V6(ip) => !(ip.is_unspecified() || ip.is_multicast()),
    }
}
