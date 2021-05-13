use serde::{Deserialize, Serialize};

use crate::parse_dns::DnsPayload;

#[derive(Serialize, Deserialize, Debug)]
pub struct LogRecord {
    pub id: u32,
    pub prim_id: u32,
    pub ts: f64,
    pub payload: DnsPayload,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PrimaryDomainStats {
    pub id: u32,
    pub length: u8,
    pub count: u32,
}
