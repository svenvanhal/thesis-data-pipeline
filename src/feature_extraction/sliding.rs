use std::collections::VecDeque;

use crate::feature_extraction::feature_vector::{FeatureVector, FixedWindowFeatureVector, TimeWindowFeatureVector};
use crate::feature_extraction::state::WindowState;
use crate::parse_dns::DnsPayload;
use crate::shared_interface::LogRecord;

impl TimeWindowFeatureVector {
    pub fn extract_for_domain(duration: f32, queries: Vec<LogRecord>, primary_domain_length: u8) -> Vec<FeatureVector> {
        let mut time_window = TimeWindow::new(duration, primary_domain_length);

        queries.into_iter()
            .map(|record| FeatureVector::Time(time_window.process_entry(record.id, record.ts, record.payload)))
            .collect()
    }
}


impl FixedWindowFeatureVector {
    pub fn extract_for_domain(size: usize, queries: Vec<LogRecord>, primary_domain_length: u8) -> Vec<FeatureVector> {
        let mut fixed_window = FixedWindow::new(size, primary_domain_length);

        queries.into_iter()
            .map(|record| FeatureVector::Fixed(fixed_window.process_entry(record.id, record.payload)))
            .collect()
    }
}

pub struct TimeWindow {
    window_size: f32,
    open_space: f32,
    content: VecDeque<(f64, DnsPayload)>,
    window_state: WindowState,
}

impl TimeWindow {
    pub fn new(duration: f32, primary_domain_length: u8) -> Self {
        Self {
            window_size: duration,
            open_space: (253 - primary_domain_length - 1) as f32,
            content: VecDeque::new(),
            window_state: WindowState::new(),
        }
    }

    pub fn process_entry(&mut self, id: usize, ts: f64, new_entry: DnsPayload) -> TimeWindowFeatureVector {

        // Calculate new minimum timestamp in the queue
        let min_ts = ts - self.window_size as f64;

        // Remove expired items
        while let Some(front) = self.content.front() {
            if front.0 >= min_ts { break; }

            // Pop expired (unwrap safe here because we know we have a value)
            let (_, payload) = self.content.pop_front().unwrap();
            self.window_state.remove(&payload);
        }

        // Update window state (accumulators) and subsequently add entry to window buffer
        self.window_state.add(&new_entry);
        self.content.push_back((ts, new_entry));

        // Construct features
        TimeWindowFeatureVector::from_window_state(id, &self.window_state, &self.open_space, &self.window_size)
    }
}

pub struct FixedWindow {
    window_size: usize,
    open_space: f32,
    content: VecDeque<DnsPayload>,
    window_state: WindowState,
}

impl FixedWindow {
    pub fn new(size: usize, primary_domain_length: u8) -> Self {
        Self {
            window_size: size,
            open_space: (253 - (primary_domain_length + 1)) as f32,
            content: VecDeque::new(),
            window_state: WindowState::new(),
        }
    }

    pub fn process_entry(&mut self, id: usize, new_entry: DnsPayload) -> FixedWindowFeatureVector {

        // Pop expired
        if self.content.len() >= self.window_size {
            // (unwrap safe here because we know we have a value)
            let payload = self.content.pop_front().unwrap();
            self.window_state.remove(&payload);

            drop(payload);
        }

        // Update window state (accumulators) and subsequently add entry to window buffer
        self.window_state.add(&new_entry);
        self.content.push_back(new_entry);

        // Construct features
        FixedWindowFeatureVector::from_window_state(id, &self.window_state, &self.open_space)
    }
}
