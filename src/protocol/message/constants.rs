//! Useful message constants.
//!
//! The `*_COMMAND` constants are to be included in message headers to indicate which message is
//! being sent.

/// Magic length (4 bytes)
pub const MAGIC_LEN: usize = 4;

/// Message header length (24 bytes).
pub const HEADER_LEN: usize = 24;
/// Maximum message length (2 MiB).
pub const MAX_MESSAGE_LEN: usize = 2 * 1024 * 1024;

/// The current network protocol version number.
///
/// Mainnet is still NU6.3. ZIP 204 assigns NU7 minimums of 170180 on Testnet
/// and 170190 on Mainnet, but the Mainnet activation height is not assigned.
/// Do not advertise 170190 on Mainnet until that height is published.
pub const NU6_3_PROTOCOL_VERSION: u32 = 170_160;
pub const PROTOCOL_VERSION: u32 = NU6_3_PROTOCOL_VERSION;
pub const NU7_TESTNET_PROTOCOL_VERSION: u32 = 170_180;
pub const NU7_MAINNET_PROTOCOL_VERSION: u32 = 170_190;
/// The current network version identifier.
pub const MAGIC_TESTNET: [u8; MAGIC_LEN] = [0xfa, 0x1a, 0xf9, 0xbf];
pub const MAGIC_MAINNET: [u8; MAGIC_LEN] = [0x24, 0xe9, 0x27, 0x64];

/// Version message user agent
pub const USER_AGENT: &str = "/ZigguratCrawler:0.2.0/";
/// NU6.3 / Ironwood activation height. Advertise at least this so peers
/// do not treat the crawler as an unsynced IBD node.
pub const NU6_3_MAINNET_ACTIVATION_HEIGHT: i32 = 3_428_143;
pub const DEFAULT_START_HEIGHT: i32 = NU6_3_MAINNET_ACTIVATION_HEIGHT;
/// Public Testnet NU7 activation height (ZIP 259 / Zebra 7.0.0-rc.0).
pub const NU7_TESTNET_ACTIVATION_HEIGHT: i32 = 4_465_026;

#[cfg(test)]
pub const MAGIC: [u8; MAGIC_LEN] = MAGIC_TESTNET;
#[cfg(all(not(test), not(feature = "crawler")))]
pub const MAGIC: [u8; MAGIC_LEN] = MAGIC_MAINNET;
#[cfg(all(not(test), feature = "crawler"))]
pub const MAGIC: [u8; MAGIC_LEN] = MAGIC_MAINNET;

use std::sync::OnceLock;

static NETWORK_MAGIC_OVERRIDE: OnceLock<[u8; MAGIC_LEN]> = OnceLock::new();

/// Selects the magic written on outbound crawler frames. Inbound decode already
/// accepts the header magic as sent. Unset means the compile-time `MAGIC`.
pub fn set_network_magic(magic: [u8; MAGIC_LEN]) {
    let _ = NETWORK_MAGIC_OVERRIDE.set(magic);
}

pub fn network_magic() -> [u8; MAGIC_LEN] {
    NETWORK_MAGIC_OVERRIDE.get().copied().unwrap_or(MAGIC)
}

pub const COMMAND_LEN: usize = 12;

// Message command bytes.
pub const VERSION_COMMAND: [u8; COMMAND_LEN] = *b"version\0\0\0\0\0";
pub const VERACK_COMMAND: [u8; COMMAND_LEN] = *b"verack\0\0\0\0\0\0";
pub const PING_COMMAND: [u8; COMMAND_LEN] = *b"ping\0\0\0\0\0\0\0\0";
pub const PONG_COMMAND: [u8; COMMAND_LEN] = *b"pong\0\0\0\0\0\0\0\0";
pub const GETADDR_COMMAND: [u8; COMMAND_LEN] = *b"getaddr\0\0\0\0\0";
pub const ADDR_COMMAND: [u8; COMMAND_LEN] = *b"addr\0\0\0\0\0\0\0\0";
pub const GETHEADERS_COMMAND: [u8; COMMAND_LEN] = *b"getheaders\0\0";
pub const HEADERS_COMMAND: [u8; COMMAND_LEN] = *b"headers\0\0\0\0\0";
pub const GETBLOCKS_COMMAND: [u8; COMMAND_LEN] = *b"getblocks\0\0\0";
pub const BLOCK_COMMAND: [u8; COMMAND_LEN] = *b"block\0\0\0\0\0\0\0";
pub const GETDATA_COMMAND: [u8; COMMAND_LEN] = *b"getdata\0\0\0\0\0";
pub const INV_COMMAND: [u8; COMMAND_LEN] = *b"inv\0\0\0\0\0\0\0\0\0";
pub const NOTFOUND_COMMAND: [u8; COMMAND_LEN] = *b"notfound\0\0\0\0";
pub const MEMPOOL_COMMAND: [u8; COMMAND_LEN] = *b"mempool\0\0\0\0\0";
pub const TX_COMMAND: [u8; COMMAND_LEN] = *b"tx\0\0\0\0\0\0\0\0\0\0";
pub const REJECT_COMMAND: [u8; COMMAND_LEN] = *b"reject\0\0\0\0\0\0";
pub const FILTERLOAD_COMMAND: [u8; COMMAND_LEN] = *b"filterload\0\0";
pub const FILTERADD_COMMAND: [u8; COMMAND_LEN] = *b"filteradd\0\0\0";
pub const FILTERCLEAR_COMMAND: [u8; COMMAND_LEN] = *b"filterclear\0";
pub const ALERT_COMMAND: [u8; COMMAND_LEN] = *b"alert\0\0\0\0\0\0\0";
// Bitcoin-inherited / ZIP-155 commands seen on live Zcash peers.
// Unknown commands must be ignored, not treated as a decode error.
pub const SENDHEADERS_COMMAND: [u8; COMMAND_LEN] = *b"sendheaders\0";
pub const SENDADDRV2_COMMAND: [u8; COMMAND_LEN] = *b"sendaddrv2\0\0";
pub const ADDRV2_COMMAND: [u8; COMMAND_LEN] = *b"addrv2\0\0\0\0\0\0";
pub const SENDCMPCT_COMMAND: [u8; COMMAND_LEN] = *b"sendcmpct\0\0\0";
pub const FEEFILTER_COMMAND: [u8; COMMAND_LEN] = *b"feefilter\0\0\0";
pub const WTXIDRELAY_COMMAND: [u8; COMMAND_LEN] = *b"wtxidrelay\0\0";
