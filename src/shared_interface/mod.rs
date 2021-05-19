use std::fmt;

use serde::{Deserialize, Serialize};

use crate::parse_dns::DnsPayload;

pub type SerializedLogEntry = (u32, LogRecord);

#[derive(Serialize, Deserialize, Debug)]
pub struct LogRecord {
    pub id: usize,
    pub ts: f64,
    pub payload: DnsPayload,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PrimaryDomainStats {
    pub id: u32,
    pub length: u8,
    pub count: usize,
}

impl fmt::Display for LogRecord {
    // This trait requires `fmt` with this exact signature.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let pl = self.payload.labels.iter().map(|label| match std::str::from_utf8(label) {
            Ok(str) => str.to_owned(),
            Err(_) => format!("{:?}", label)
        }).collect::<Vec<String>>();
        write!(f, "LogRecord<id={}, ts={}, payload={}>", self.id, self.ts, pl.join("."))
    }
}