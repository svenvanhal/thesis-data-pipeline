use std::collections::BTreeMap;
use std::f64::consts::LN_2;

use serde::Serialize;

use crate::feature_extraction::FeatureVector;
use crate::parse_dns::DnsPayload;
use crate::shared_interface::LogRecord;

#[prefix_all("pl_")]
#[derive(Default, Debug, Serialize, PartialEq)]
pub struct PayloadFeatureVector {
    pub id: usize,
    pub n_unique: u8,
    pub ratio_unique: f32,
    pub n_digits: u8,
    pub n_invalid: u8,
    pub n_labels: u8,
    pub avg_label_length: f32,
    pub max_label_length: u8,
    pub entropy: f32,
    pub fill_ratio: f32,
}

impl PayloadFeatureVector {
    pub fn extract_for_domain(queries: Vec<LogRecord>, primary_domain_length: u8) -> Vec<FeatureVector> {
        queries.into_iter()
            .map(|record| FeatureVector::Payload(payload_features(record.id, &record.payload, primary_domain_length)))
            .collect()
    }
}

pub fn payload_features(id: usize, entry: &DnsPayload, primary_domain_length: u8) -> PayloadFeatureVector {
    let n_labels = entry.labels.len() as u8;

    // Bail if no labels (e.g. only dots in input string)
    // if n_labels == 0 { return None; }

    // Average label length and maximum label length
    let label_lengths: Vec<u8> = entry.labels.iter().map(|label| label.len() as u8).collect();
    let avg_label_length = (label_lengths.iter().sum::<u8>() as f32) / label_lengths.len() as f32;
    let max_label_length = *label_lengths.iter().max().unwrap();

    // Character counts
    let mut n_digits: u8 = 0;
    let mut n_invalid: u8 = 0;

    // Entropy
    let mut char_map: BTreeMap<u8, u8> = BTreeMap::new();
    let mut ascii_map: [u8; 128] = [0; 128];

    // String length as float for entropy division
    let mut n_total: f64 = 0.;

    for label in entry.labels.iter() {
        for ch in label.iter() {
            if *ch == b'.' { continue; }
            n_total += 1.;

            if ch.is_ascii() {
                // Add to ASCII map (fast path for entropy calculation)
                ascii_map[*ch as usize] += 1;

                match ch {
                    b'0'..=b'9' => { n_digits += 1 }
                    b'a'..=b'z' | b'A'..=b'Z' | b'-' | b'_' => {}
                    _ => { n_invalid += 1 }
                }
            } else {
                // Add to char map (slow path for entropy calculation)
                *char_map.entry(*ch).or_insert(0) += 1;

                n_invalid += 1;
            }
        }
    }

    let mut n_unique: u8 = 0;

    let result = char_map
        .values()
        .chain(ascii_map.iter())
        .fold(0.0, |acc, &c| {
            match c {
                0 => acc,
                c => {
                    n_unique += 1;
                    acc + (c as f64 * (c as f64 / n_total).ln())
                }
            }
        })
        .abs();

    let entropy: f32 = (result / (n_total * LN_2)) as f32;
    let ratio_unique: f32 = n_unique as f32 / n_total as f32;

    // Fraction of the total available query space that is used
    let fill_ratio = entry.payload_len as f32 / (253 - (primary_domain_length + 1)) as f32;

    PayloadFeatureVector {
        id,
        n_unique,
        ratio_unique,
        n_digits,
        n_invalid,
        n_labels,
        avg_label_length,
        max_label_length,
        entropy,
        fill_ratio,
    }
}

#[cfg(test)]
mod tests {
    use crate::feature_extraction::payload::{payload_features, PayloadFeatureVector};
    use crate::parse_dns::DnsPayload;

    #[test]
    fn smoke_test() {
        let payload = DnsPayload {
            labels: vec![b"aabbcc".to_vec(), b"0011223344".to_vec()],
            payload_len: 17,
        };
        let prim_len = 10;

        let expected = PayloadFeatureVector {
            id: 0,
            n_unique: 8,
            ratio_unique: 0.5,
            n_digits: 10,
            n_invalid: 0,
            n_labels: 2,
            avg_label_length: 8.0,
            max_label_length: 10,
            entropy: 3.0,
            fill_ratio: 0.07024793388429752066115702479339,
        };

        assert_eq!(expected, payload_features(0, &payload, prim_len));
    }
}
