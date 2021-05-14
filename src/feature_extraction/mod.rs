use std::rc::Rc;

use crate::feature_extraction::feature_vector::FeatureVector;
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


pub fn extract_features_per_domain(opts: &ExtractOpts, queries: Vec<(f64, DnsPayload)>, primary_domain_length: u8) -> Vec<Vec<FeatureVector>> {
    let mut n_fv: usize = if opts.payload { 1 } else { 0 };

    // Create sliding windows
    let mut time_window = match opts.time {
        None => None,
        Some(duration) => {
            n_fv += 1;
            Some(TimeWindow::new(duration, primary_domain_length))
        }
    };

    let mut fixed_window = match opts.fixed {
        None => None,
        Some(size) => {
            n_fv += 1;
            Some(FixedWindow::new(size, primary_domain_length))
        }
    };

    // Process all entries in window
    queries.into_iter()
        .map(|(ts, payload)| {
            let payload = Rc::new(payload);

            let mut fv: Vec<FeatureVector> = Vec::with_capacity(n_fv);

            if opts.payload {
                fv.push(payload_features(&payload, primary_domain_length))
            }

            match &mut time_window {
                None => {}
                Some(win) => fv.push(win.process_entry(ts.clone(), payload.clone()))
            }

            match &mut fixed_window {
                None => {}
                Some(win) => fv.push(win.process_entry(payload.clone()))
            }

            fv
        })
        .collect::<Vec<_>>()
}
