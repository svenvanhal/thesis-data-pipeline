use crate::feature_extraction::feature_vector::{FixedWindowFeatureVector, PayloadFeatureVector, TimeWindowFeatureVector, FeatureVector};
use crate::shared_interface::LogRecord;

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
