use std::collections::VecDeque;

use serde::Serialize;

use crate::feature_extraction::FeatureVector;
use crate::feature_extraction::state::WindowState;
use crate::parse_dns::DnsPayload;
use crate::shared_interface::LogRecord;

#[prefix_all("win_time_")]
#[derive(Default, Debug, Serialize, PartialEq)]
pub struct TimeWindowFeatureVector {
    pub id: usize,
    pub n_unique_labels: usize,
    pub unique_query_rate: f32,
    pub entropy: f32,
    pub unique_transfer_rate: f32,
    pub avg_unique_label_length: f32,
    pub unique_fill_ratio: f32,
    pub max_label_length: u8,
    pub unique_query_ratio: f32,
}

#[prefix_all("win_fixed_")]
#[derive(Default, Debug, Serialize, PartialEq)]
pub struct FixedWindowFeatureVector {
    pub id: usize,
    pub n_unique_labels: usize,
    pub entropy: f32,
    pub avg_unique_label_length: f32,
    pub unique_fill_ratio: f32,
    pub max_label_length: u8,
    pub unique_query_ratio: f32,
}


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


#[cfg(test)]
mod tests {
    use crate::feature_extraction::sliding::{FixedWindow, FixedWindowFeatureVector, TimeWindow, TimeWindowFeatureVector};
    use crate::parse_dns::DnsPayload;

    #[test]
    fn smoke_test_fixed() {
        let mut window = FixedWindow::new(2, 10);

        let payload_1 = DnsPayload {
            labels: vec![b"aabbcc".to_vec(), b"0011223344".to_vec()],
            payload_len: 17,
        };

        let payload_2 = DnsPayload {
            labels: vec![b"aa".to_vec(), b"00".to_vec()],
            payload_len: 5,
        };

        let expected_1 = FixedWindowFeatureVector {
            id: 1,
            n_unique_labels: 2,
            entropy: 3.0,
            avg_unique_label_length: 8.0,
            unique_fill_ratio: 0.07024793388429752066115702479339,
            max_label_length: 10,
            unique_query_ratio: 1.0,
        };

        let expected_2 = FixedWindowFeatureVector {
            id: 2,
            n_unique_labels: 4,
            entropy: 2.9219280948873623,
            avg_unique_label_length: 5.0,
            unique_fill_ratio: 0.0454545454545454545454,
            max_label_length: 10,
            unique_query_ratio: 1.0,
        };

        assert_eq!(expected_1, window.process_entry(1, payload_1));
        assert_eq!(expected_2, window.process_entry(2, payload_2));
    }


    #[test]
    fn smoke_test_time() {
        let mut window = TimeWindow::new(1., 10);

        let payload_1 = DnsPayload {
            labels: vec![b"aabbcc".to_vec(), b"0011223344".to_vec()],
            payload_len: 17,
        };

        let payload_2 = DnsPayload {
            labels: vec![b"aa".to_vec(), b"00".to_vec()],
            payload_len: 5,
        };

        let payload_3 = DnsPayload {
            labels: vec![b"aabbcc".to_vec(), b"0011223344".to_vec()],
            payload_len: 17,
        };

        let expected_1 = TimeWindowFeatureVector {
            id: 1,
            n_unique_labels: 2,
            unique_query_rate: 1.0,
            entropy: 3.0,
            unique_transfer_rate: 16.0,
            avg_unique_label_length: 8.0,
            unique_fill_ratio: 0.07024793388429752066115702479339,
            max_label_length: 10,
            unique_query_ratio: 1.0,
        };

        let expected_2 = TimeWindowFeatureVector {
            id: 2,
            n_unique_labels: 4,
            unique_query_rate: 2.0,
            entropy: 2.9219280948873623,
            unique_transfer_rate: 20.0,
            avg_unique_label_length: 5.0,
            unique_fill_ratio: 0.0454545454545454545454,
            max_label_length: 10,
            unique_query_ratio: 1.0,
        };

        assert_eq!(expected_1, window.process_entry(1, 0.0, payload_1));
        assert_eq!(expected_2, window.process_entry(2, 0.1, payload_2));

        // Same as payload 1, but later and outside previous window, should produce same result
        assert_eq!(expected_1, window.process_entry(1, 10.0, payload_3));
    }

    #[test]
    fn expire_time() {
        let mut window = TimeWindow::new(1., 10);
        assert_eq!(0, window.content.len());

        window.process_entry(1, 0.0, DnsPayload { labels: vec![b"a".to_vec()], payload_len: 1 });
        assert_eq!(1, window.content.len());

        window.process_entry(1, 1.0, DnsPayload { labels: vec![b"a".to_vec()], payload_len: 1 });
        assert_eq!(2, window.content.len());

        window.process_entry(1, 10.0, DnsPayload { labels: vec![b"a".to_vec()], payload_len: 1 });
        assert_eq!(1, window.content.len());

        window.process_entry(1, 10.1, DnsPayload { labels: vec![b"a".to_vec()], payload_len: 1 });
        assert_eq!(2, window.content.len());

        window.process_entry(1, 15.0, DnsPayload { labels: vec![b"a".to_vec()], payload_len: 1 });
        assert_eq!(1, window.content.len());
    }

    #[test]
    fn expire_fixed() {
        let mut window = FixedWindow::new(2, 10);
        assert_eq!(0, window.content.len());

        window.process_entry(1, DnsPayload { labels: vec![b"a".to_vec()], payload_len: 1 });
        assert_eq!(1, window.content.len());

        window.process_entry(1, DnsPayload { labels: vec![b"a".to_vec()], payload_len: 1 });
        assert_eq!(2, window.content.len());

        window.process_entry(1, DnsPayload { labels: vec![b"a".to_vec()], payload_len: 1 });
        assert_eq!(2, window.content.len());

        window.process_entry(1, DnsPayload { labels: vec![b"a".to_vec()], payload_len: 1 });
        assert_eq!(2, window.content.len());
    }
}
