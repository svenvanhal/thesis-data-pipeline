use serde::Serialize;

#[prefix_all("pl_")]
#[derive(Default, Debug, Serialize, PartialEq)]
pub struct PayloadFeatureVector {
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

#[prefix_all("win_time_")]
#[derive(Default, Debug, Serialize, PartialEq)]
pub struct TimeWindowFeatureVector {
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
    pub n_unique_labels: usize,
    pub entropy: f32,
    pub avg_unique_label_length: f32,
    pub unique_fill_ratio: f32,
    pub max_label_length: u8,
    pub unique_query_ratio: f32,
}

#[derive(Serialize)]
pub enum FeatureVector {
    Payload(PayloadFeatureVector),
    Time(TimeWindowFeatureVector),
    Fixed(FixedWindowFeatureVector),
}

// TODO: find a better solution to output a dynamic number of features
#[derive(Serialize)]
pub struct FeatureRow(
    #[serde(skip_serializing_if = "Option::is_none")]
    pub Option<FeatureVector>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub Option<FeatureVector>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub Option<FeatureVector>,
);
