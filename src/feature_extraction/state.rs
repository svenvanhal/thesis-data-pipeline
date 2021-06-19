use std::collections::BTreeMap;
use std::f64::consts::LN_2;

use counter::Counter;

use crate::feature_extraction::sliding::{FixedWindowFeatureVector, TimeWindowFeatureVector};
use crate::parse_dns::DnsPayload;

pub struct WindowState {
    // Accumulators
    pub n_queries: usize,
    pub unique_queries: Counter<Vec<Vec<u8>>>,
    pub n_labels: usize,
    pub unique_labels: Counter<Vec<u8>>,
    pub total_label_len: usize,
    pub total_unique_label_len: usize,
    pub total_unique_query_len: usize,
    pub max_label_len: usize,

    // Entropy
    char_map: BTreeMap<u8, usize>,
    ascii_map: [usize; 128],
}

impl Default for WindowState {
    fn default() -> Self {
        Self::new()
    }
}


impl WindowState {
    pub fn new() -> Self {
        WindowState {
            n_queries: 0,
            n_labels: 0,
            total_label_len: 0,
            total_unique_label_len: 0,
            total_unique_query_len: 0,
            max_label_len: 0,

            unique_queries: Counter::new(),
            unique_labels: Counter::new(),

            // Entropy
            char_map: BTreeMap::new(),
            ascii_map: [0; 128],
        }
    }

    pub fn add(&mut self, entry: &DnsPayload) {
        self.n_queries += 1;

        // Update unique query counter
        if let Some(entry) = self.unique_queries.get_mut(&entry.labels) {
            *entry += 1
        } else {
            self.unique_queries.insert(entry.labels.clone(), 1);
            self.total_unique_query_len += entry.payload_len as usize;
        }

        // Update accumulators
        self.n_labels += entry.labels.len();

        for label in entry.labels.iter() {

            // Update total (unique) label length
            self.total_label_len += label.len();
            if !self.unique_labels.contains_key(label) {
                self.total_unique_label_len += label.len()
            }

            // Update unique label counter
            if let Some(entry) = self.unique_labels.get_mut(label) {
                *entry += 1
            } else { self.unique_labels.insert(label.clone(), 1); }

            // Update max label length
            if label.len() > self.max_label_len {
                self.max_label_len = label.len();
            }

            // Update entropy
            for ch in label.iter() {
                match ch {
                    b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z' | b'-' | b'_' => self.ascii_map[*ch as usize] += 1,
                    _ => *self.char_map.entry(*ch).or_insert(0) += 1
                }
            }
        }
    }

    pub fn remove(&mut self, removed: &DnsPayload) {
        self.n_queries -= 1;

        // Update unique query counter
        // Below adapted from Counter.subtract (crate)
        if let Some(entry) = self.unique_queries.get_mut(&removed.labels) {
            if *entry <= 1 {
                self.unique_queries.remove(&removed.labels);
                self.total_unique_query_len -= removed.payload_len as usize;
            } else {
                *entry -= 1;
            }
        }

        // Update accumulators
        self.n_labels -= removed.labels.len();

        let mut update_max = false;
        for label in removed.labels.iter() {
            self.total_label_len -= label.len();

            // Below adapted from Counter.subtract (crate)
            if let Some(entry) = self.unique_labels.get_mut(label) {
                if *entry <= 1 {
                    self.unique_labels.remove(label);
                    self.total_unique_label_len -= label.len();

                    // Find out if we need to update the max label length (only when we remove this label)
                    if !update_max && label.len() == self.max_label_len {
                        update_max = true;
                    }
                } else {
                    *entry -= 1;
                }
            }

            // Update entropy
            for ch in label.iter() {
                match ch {
                    b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z' | b'-' | b'_' => self.ascii_map[*ch as usize] -= 1,
                    _ => { *self.char_map.entry(*ch).or_insert(0) -= 1; }
                }
            }
        }

        // Find new maximum label length (optimized for new_max = (old_max || old_max-1) cases)
        if update_max {
            let mut max: usize = 0;
            for l in self.unique_labels.keys() {
                if l.len() >= (self.max_label_len - 1) {
                    max = l.len();
                    break;
                } else if l.len() > max {
                    max = l.len();
                }
            }
            self.max_label_len = max;
        }
    }

    pub fn get_entropy(&self) -> f32 {
        (self.char_map
            .values()
            .chain(self.ascii_map.iter())
            .fold(0.0, |acc, &c| {
                match c {
                    0 => acc,
                    c => {
                        let c = c as f64;
                        acc + (c * (c / self.total_label_len as f64).ln())
                    }
                }
            })
            .abs() / (self.total_label_len as f64 * LN_2)) as f32
    }
}

impl TimeWindowFeatureVector {
    pub fn from_window_state(id: usize, ws: &WindowState, open_space: &f32, window_duration: &f32) -> Self {
        let n_unique_queries: f32 = ws.unique_queries.len() as f32;
        let n_unique_labels: usize = ws.unique_labels.len();
        let unique_fill_ratio: f32 = ((ws.total_unique_label_len + n_unique_labels) as f32 - n_unique_queries) / (open_space * n_unique_queries);

        let entropy: f32 = ws.get_entropy();

        // TODO: change total_unique_label_len to total_unique_query_len?

        let unique_query_rate = n_unique_queries / window_duration;
        let unique_transfer_rate = ws.total_unique_label_len as f32 / window_duration;

        let avg_unique_label_length = ws.total_unique_label_len as f32 / n_unique_labels as f32;
        let max_label_length = ws.max_label_len as u8;
        let unique_query_ratio = n_unique_queries / ws.n_queries as f32;

        // Return new feature vector
        TimeWindowFeatureVector {
            id,
            n_unique_labels,
            unique_query_rate,
            entropy,
            unique_transfer_rate,
            avg_unique_label_length,
            unique_fill_ratio,
            max_label_length,
            unique_query_ratio,
        }
    }
}

impl FixedWindowFeatureVector {
    pub fn from_window_state(id: usize, ws: &WindowState, open_space: &f32) -> Self {
        let n_unique_queries: f32 = ws.unique_queries.len() as f32;
        let n_unique_labels: usize = ws.unique_labels.len();
        let unique_fill_ratio: f32 = ((ws.total_unique_label_len + n_unique_labels) as f32 - n_unique_queries) / (open_space * n_unique_queries);

        let entropy: f32 = ws.get_entropy();

        let avg_unique_label_length = ws.total_unique_label_len as f32 / n_unique_labels as f32;
        let max_label_length = ws.max_label_len as u8;
        let unique_query_ratio = n_unique_queries / ws.n_queries as f32;

        // Return new feature vector
        FixedWindowFeatureVector {
            id,
            n_unique_labels,
            entropy,
            avg_unique_label_length,
            unique_fill_ratio,
            max_label_length,
            unique_query_ratio,
        }
    }
}
