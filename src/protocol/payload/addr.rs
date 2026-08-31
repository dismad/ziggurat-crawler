//! Network address types.

use std::{
    convert::TryInto,
    io,
    net::{IpAddr, IpAddr::*, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use bytes::{Buf, BufMut};
use time::OffsetDateTime;

use crate::protocol::payload::{
    codec::Codec, read_n_bytes, read_short_timestamp, VarInt,
};

/// A list of network addresses, used for peering.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Addr {
    pub addrs: Vec<NetworkAddr>,
}

impl Addr {
    /// Returns an `Addr` with no addresses.
    pub fn empty() -> Self {
        Self { addrs: Vec::new() }
    }

    /// Returns an `Addr` with the given addresses.
    pub fn new(addrs: Vec<NetworkAddr>) -> Self {
        Addr { addrs }
    }

    /// Returns an iterator over the list of network addresses.
    pub fn iter(&self) -> std::slice::Iter<NetworkAddr> {
        self.addrs.iter()
    }

    /// Decode a ZIP-155 / BIP-155 `addrv2` payload.
    ///
    /// Non-routable network IDs (Tor, I2P, CJDNS, unknown) are skipped so the
    /// crawler only stores addresses it can actually dial.
    pub fn decode_v2<B: Buf>(bytes: &mut B) -> io::Result<Self> {
        let count = *VarInt::decode(bytes)?;
        let mut addrs = Vec::with_capacity(count.min(1000));
        for _ in 0..count {
            if let Some(addr) = NetworkAddr::decode_v2(bytes)? {
                addrs.push(addr);
            }
        }
        Ok(Self { addrs })
    }
}

impl Codec for Addr {
    fn encode<B: BufMut>(&self, buffer: &mut B) -> io::Result<()> {
        self.addrs.encode(buffer)
    }

    fn decode<B: Buf>(bytes: &mut B) -> io::Result<Self> {
        Ok(Self::new(Vec::decode(bytes)?))
    }
}

/// A network address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkAddr {
    /// The last time this address was seen.
    /// Note: Present only when version is >= 31402
    pub last_seen: Option<OffsetDateTime>,
    /// The services supported by this address.
    pub services: u64,
    /// The socket address.
    pub addr: SocketAddr,
}

impl NetworkAddr {
    /// Creates a new NetworkAddr with the given socket address,
    /// `last_seen=OffsetDateTime::now_utc()`,
    /// and `services=1` (only `NODE_NETWORK` is enabled).
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            last_seen: Some(OffsetDateTime::now_utc()),
            services: 1,
            addr,
        }
    }

    pub fn encode_without_timestamp<B: BufMut>(&self, buffer: &mut B) -> io::Result<()> {
        buffer.put_u64_le(self.services);

        let (ip, port) = match self.addr {
            SocketAddr::V4(v4) => (v4.ip().to_ipv6_mapped(), v4.port()),
            SocketAddr::V6(v6) => (*v6.ip(), v6.port()),
        };

        buffer.put_slice(&ip.octets());
        buffer.put_u16(port);

        Ok(())
    }

    pub(super) fn decode_without_timestamp<B: Buf>(bytes: &mut B) -> io::Result<Self> {
        let services = u64::from_le_bytes(read_n_bytes(bytes)?);

        if bytes.remaining() < 16 {
            return Err(io::ErrorKind::InvalidData.into());
        }

        let mut octets = [0u8; 16];
        bytes.copy_to_slice(&mut octets);
        let v6_addr = Ipv6Addr::from(octets);

        let ip_addr = match v6_addr.to_ipv4() {
            Some(v4_addr) => V4(v4_addr),
            None => V6(v6_addr),
        };

        let port = u16::from_be_bytes(read_n_bytes(bytes)?);

        Ok(Self {
            last_seen: None,
            services,
            addr: SocketAddr::new(ip_addr, port),
        })
    }

    /// Decode one ZIP-155 address. Returns `Ok(None)` for non-IP network IDs.
    pub(super) fn decode_v2<B: Buf>(bytes: &mut B) -> io::Result<Option<Self>> {
        let timestamp = read_short_timestamp(bytes)?;
        let services = *VarInt::decode(bytes)? as u64;
        let network_id = u8::from_le_bytes(read_n_bytes(bytes)?);
        let addr_len = *VarInt::decode(bytes)?;

        if bytes.remaining() < addr_len + 2 {
            return Err(io::ErrorKind::InvalidData.into());
        }

        let mut addr_bytes = vec![0u8; addr_len];
        bytes.copy_to_slice(&mut addr_bytes);
        let port = u16::from_be_bytes(read_n_bytes(bytes)?);

        if port == 0 {
            return Ok(None);
        }

        const NET_IPV4: u8 = 0x01;
        const NET_IPV6: u8 = 0x02;

        let ip = match (network_id, addr_len) {
            (NET_IPV4, 4) => IpAddr::V4(Ipv4Addr::new(
                addr_bytes[0],
                addr_bytes[1],
                addr_bytes[2],
                addr_bytes[3],
            )),
            (NET_IPV6, 16) => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&addr_bytes);
                let v6 = Ipv6Addr::from(octets);
                match v6.to_ipv4() {
                    Some(v4) => IpAddr::V4(v4),
                    None => IpAddr::V6(v6),
                }
            }
            _ => return Ok(None),
        };

        if ip.is_unspecified() || ip.is_multicast() {
            return Ok(None);
        }

        Ok(Some(Self {
            last_seen: Some(timestamp),
            services,
            addr: SocketAddr::new(ip, port),
        }))
    }
}

impl Codec for NetworkAddr {
    fn encode<B: BufMut>(&self, buffer: &mut B) -> io::Result<()> {
        let timestamp: u32 = self
            .last_seen
            .expect("missing timestamp")
            .unix_timestamp()
            .try_into()
            .unwrap();
        buffer.put_u32_le(timestamp);

        self.encode_without_timestamp(buffer)?;

        Ok(())
    }

    fn decode<B: Buf>(bytes: &mut B) -> io::Result<Self> {
        let timestamp = read_short_timestamp(bytes)?;
        let without_timestamp = Self::decode_without_timestamp(bytes)?;

        Ok(Self {
            last_seen: Some(timestamp),
            ..without_timestamp
        })
    }
}