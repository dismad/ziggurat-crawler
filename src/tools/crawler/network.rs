use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    time::{Duration, Instant},
};

use parking_lot::RwLock;
use ziggurat_core_crawler::connection::KnownConnection;
use ziggurat_zcash::protocol::payload::{ProtocolVersion, VarStr};

/// The elapsed time before a connection should be regarded as inactive.
pub const LAST_SEEN_CUTOFF: u64 = 10 * 60;

#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub enum ConnectionState {
    /// The node is not connected.
    #[default]
    Disconnected,
    /// The node is connected.
    Connected,
}

/// A node encountered in the network or obtained from one of the peers.
#[derive(Debug, Default, Clone)]
pub struct KnownNode {
    // The address is omitted, as it's a key in the owning HashMap.
    /// The last time the node was successfully connected to.
    pub last_connected: Option<Instant>,
    /// The time it took to complete a connection.
    pub handshake_time: Option<Duration>,
    /// The node's protocol version.
    pub protocol_version: Option<ProtocolVersion>,
    /// The node's user agent.
    pub user_agent: Option<VarStr>,
    /// The node's block height.
    pub start_height: Option<i32>,
    /// The number of services supported by the node.
    pub services: Option<u64>,
    /// The number of subsequent connection errors.
    pub connection_failures: u8,
    /// How many `getaddr` messages we have sent on the current connection.
    pub getaddr_sent: u8,
    /// True once this peer sent a usable `addr` / `addrv2` dump.
    pub received_addr: bool,
    /// The node's state.
    pub state: ConnectionState,
}

impl KnownNode {
    /// Parsed Zebra or Zakura identity from the version user agent.
    pub fn impl_version(
        &self,
    ) -> Option<(crate::user_agent::ImplKind, crate::user_agent::NodeVersion)> {
        self.user_agent
            .as_ref()
            .and_then(|ua| crate::user_agent::classify(&ua.0))
    }

    pub fn is_zebra_or_zakura(&self) -> bool {
        self.impl_version().is_some()
    }

    /// Zebra 7.x and anything newer. Older Zebra stays in the general preferred bucket.
    pub fn is_zebra_7_plus(&self) -> bool {
        self.impl_version()
            .is_some_and(|(kind, version)| crate::user_agent::is_zebra_at_least_7(kind, version))
    }
}

/// The list of nodes and connections the crawler is aware of.
#[derive(Default)]
pub struct KnownNetwork {
    pub nodes: RwLock<HashMap<SocketAddr, KnownNode>>,
    pub connections: RwLock<HashSet<KnownConnection>>,
}

impl KnownNetwork {
    /// Extends the list of known nodes and connections.
    pub fn add_addrs(&self, source: SocketAddr, listening_addrs: &[SocketAddr]) {
        {
            let connections = &mut self.connections.write();
            for addr in listening_addrs {
                connections.insert(KnownConnection::new(source, *addr));
            }
        }
        let mut nodes = self.nodes.write();
        nodes.entry(source).or_default();
        listening_addrs.iter().for_each(|addr| {
            nodes.entry(*addr).or_default();
        });
    }

    /// Sets the node's connection state.
    pub fn set_node_state(&self, addr: SocketAddr, state: ConnectionState) {
        if let Some(node) = self.nodes.write().get_mut(&addr) {
            node.state = state;
            if state == ConnectionState::Disconnected {
                node.getaddr_sent = 0;
            }
        }
    }

    pub fn mark_received_addr(&self, addr: SocketAddr) {
        if let Some(node) = self.nodes.write().get_mut(&addr) {
            node.received_addr = true;
        }
    }

    pub fn bump_getaddr_sent(&self, addr: SocketAddr) -> u8 {
        if let Some(node) = self.nodes.write().get_mut(&addr) {
            node.getaddr_sent = node.getaddr_sent.saturating_add(1);
            node.getaddr_sent
        } else {
            0
        }
    }

    /// Returns a snapshot of the known connections.
    pub fn connections(&self) -> HashSet<KnownConnection> {
        self.connections.read().clone()
    }

    /// Returns a snapshot of the known nodes.
    pub fn nodes(&self) -> HashMap<SocketAddr, KnownNode> {
        self.nodes.read().clone()
    }

    /// Returns the number of known connections.
    pub fn num_connections(&self) -> usize {
        self.connections.read().len()
    }

    /// Returns the number of known nodes.
    pub fn num_nodes(&self) -> usize {
        self.nodes.read().len()
    }

    /// Prunes the list of known connections by removing connections last seen long ago.
    pub fn remove_old_connections(&self) {
        let mut old_conns: HashSet<KnownConnection> = HashSet::new();
        for conn in self.connections() {
            if conn.last_seen.elapsed().as_secs() > LAST_SEEN_CUTOFF {
                old_conns.insert(conn);
            }
        }

        if !old_conns.is_empty() {
            let mut conns = self.connections.write();
            for conn in old_conns {
                conns.remove(&conn);
            }
        }
    }
}
