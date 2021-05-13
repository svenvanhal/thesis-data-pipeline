use std::rc::Rc;

use serde::Serialize;

use crate::feature_extraction::feature_vector::{FixedWindowFeatureVector, PayloadFeatureVector, TimeWindowFeatureVector};
use crate::feature_extraction::payload::payload_features;
use crate::feature_extraction::sliding::{FixedWindow, TimeWindow};
use crate::parse_dns::DnsPayload;

mod sliding;
mod feature_vector;
mod payload;
mod state;

#[derive(Debug)]
pub struct ExtractOpts {
    pub payload: bool,
    pub time: Option<f32>,
    pub fixed: Option<usize>,
}

// TODO: find a better solution to output a dynamic number of features
#[derive(Debug, Serialize)]
pub struct FeatureRow(
    #[serde(skip_serializing_if = "Option::is_none")]
    Option<PayloadFeatureVector>,
    #[serde(skip_serializing_if = "Option::is_none")]
    Option<TimeWindowFeatureVector>,
    #[serde(skip_serializing_if = "Option::is_none")]
    Option<FixedWindowFeatureVector>,
);


pub fn extract_features_per_domain(opts: &ExtractOpts, queries: Vec<(f64, DnsPayload)>, primary_domain_length: u8) -> Vec<FeatureRow> {

    // Create sliding window from queries
    let payload_extractor = if opts.payload {
        |payload: &DnsPayload, prim_len: u8| Some(payload_features(&payload, prim_len))
    } else {
        |_payload: &DnsPayload, _prim_len: u8| None
    };

    let mut time_window = match opts.time {
        None => None,
        Some(duration) => Some(TimeWindow::new(duration, primary_domain_length)),
    };

    let mut fixed_window = match opts.fixed {
        None => None,
        Some(size) => Some(FixedWindow::new(size, primary_domain_length)),
    };

    // Process all entries in window
    queries.into_iter()
        .map(|(ts, payload)| {
            let ts = Rc::new(ts);
            let payload = Rc::new(payload);

            FeatureRow(
                payload_extractor(&payload, primary_domain_length),
                match &mut time_window {
                    None => None,
                    Some(win) => Some(win.process_entry(ts.clone(), payload.clone()))
                },
                match &mut fixed_window {
                    None => None,
                    Some(win) => Some(win.process_entry(payload.clone()))
                },
            )
        })
        .collect::<Vec<FeatureRow>>()
}
