use serde::Serialize;

use crate::feature_extraction::payload::PayloadFeatureVector;
use crate::feature_extraction::sliding::{FixedWindowFeatureVector, TimeWindowFeatureVector};
use crate::shared_interface::LogRecord;

mod payload;
mod sliding;
mod state;


#[derive(Serialize)]
#[serde(untagged)]
pub enum FeatureVector {
    Payload(PayloadFeatureVector),
    Time(TimeWindowFeatureVector),
    Fixed(FixedWindowFeatureVector),
}

#[derive(Debug)]
pub struct ExtractOpts {
    pub payload: bool,
    pub time: Option<f32>,
    pub fixed: Option<usize>,
}


pub fn extract_features_per_domain(opts: &ExtractOpts, queries: Vec<LogRecord>, primary_domain_length: u8) -> Vec<FeatureVector> {
    // Payload features
    if opts.payload {
        return PayloadFeatureVector::extract_for_domain(queries, primary_domain_length);
    }

    // Fixed window features
    if let Some(size) = opts.fixed {
        return FixedWindowFeatureVector::extract_for_domain(size, queries, primary_domain_length);
    }

    // Time window features
    if let Some(duration) = opts.time {
        return TimeWindowFeatureVector::extract_for_domain(duration, queries, primary_domain_length);
    }

    panic!("No feature type selected for feature extraction.")
}
