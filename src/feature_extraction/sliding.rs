use std::collections::VecDeque;
use std::rc::Rc;

use crate::feature_extraction::feature_vector::{FeatureVector, FixedWindowFeatureVector, TimeWindowFeatureVector};
use crate::feature_extraction::state::WindowState;
use crate::parse_dns::DnsPayload;

pub struct TimeWindow {
    window_size: f32,
    open_space: f32,
    content: VecDeque<(f64, Rc<DnsPayload>)>,
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

    pub fn process_entry(&mut self, ts: f64, new_entry: Rc<DnsPayload>) -> FeatureVector {

        // Calculate new minimum timestamp in the queue
        let min_ts = ts - self.window_size as f64;

        // Remove expired items
        while let Some(front) = self.content.front() {
            if front.0 >= min_ts { break; }

            // Pop expired (unwrap safe here because we know we have a value)
            let (ts, payload) = self.content.pop_front().unwrap();
            self.window_state.remove(&payload);

            drop(ts);
            drop(payload);
        }


        // Update window state (accumulators) and subsequently add entry to window buffer
        self.window_state.add(&new_entry);
        self.content.push_back((ts, new_entry.clone()));

        // Construct features
        FeatureVector::Time(TimeWindowFeatureVector::from_window_state(&self.window_state, &self.open_space, &self.window_size))
    }
}

pub struct FixedWindow {
    window_size: usize,
    open_space: f32,
    content: VecDeque<Rc<DnsPayload>>,
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

    pub fn process_entry(&mut self, new_entry: Rc<DnsPayload>) -> FeatureVector {

        // Pop expired
        if self.content.len() >= self.window_size {
            // (unwrap safe here because we know we have a value)
            let payload = self.content.pop_front().unwrap();
            self.window_state.remove(&payload);

            drop(payload);
        }

        // Update window state (accumulators) and subsequently add entry to window buffer
        self.window_state.add(&new_entry);
        self.content.push_back(new_entry.clone());

        // Construct features
        FeatureVector::Fixed(FixedWindowFeatureVector::from_window_state(&self.window_state, &self.open_space))
    }
}
