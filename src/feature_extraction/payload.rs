use std::collections::BTreeMap;
use std::f32::consts::LN_2;

use crate::feature_extraction::feature_vector::PayloadFeatureVector;
use crate::parse_dns::DnsPayload;

pub fn payload_features(entry: &DnsPayload, primary_domain_length: u8) -> PayloadFeatureVector {
    let n_labels = entry.labels.len() as u8;

    // Bail if no labels (e.g. only dots in input string)
    // TODO: this should not be possible, so check might be removed
    if n_labels == 0 {
        return PayloadFeatureVector::default();
    }

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

    // String length as f32 for entropy division
    let mut n_total: f32 = 0.;

    for label in entry.labels.iter() {
        for ch in label.iter() {
            if *ch == b'.' {
                continue;
            }

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
                    acc + (c as f32 * (c as f32 / n_total).ln())
                }
            }
        })
        .abs();

    let entropy: f32 = result / (n_total * LN_2);
    let ratio_unique: f32 = n_unique as f32 / n_total;

    // Fraction of the total available query space that is used
    let fill_ratio = entry.payload_len as f32 / (253 - (primary_domain_length + 1)) as f32;

    PayloadFeatureVector {
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
