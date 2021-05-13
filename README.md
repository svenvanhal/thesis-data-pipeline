# Thesis - Data Pipeline

Zeek `dns.log` preprocessing and feature extraction.

## Usage

Preprocess: \
`zeek-cut ts query < dns.log | cargo run --bin preprocess --release -- -r records.bin -p prim.bin`

Feature extraction: \
`cargo run --bin extract --release -- --in-records=records.bin --in-prim=prim.bin --out-features=ff.csv --payload --time=2 --fixed 10`

## Progress

Work in progress.

- [ ] Preprocessing
    - [x] ~~Fast log parsing~~
    - [x] ~~DNS name parsing~~
    - [x] ~~Validation and filtering~~
    - [x] ~~Test suite~~
    - [ ] Check test coverage and edge cases
    - [ ] Benchmark, profile and improve performance
- [ ] Feature Extraction
    - [x] ~~PoC~~
    - [ ] Comprehensive test suite
    - [ ] Improve memory footprint
    - [ ] Investigate different output format (instead of CSV, but still streamable and Python compatible)
    - [ ] Benchmark, profile and improve performance
    - [ ]

### Roadmap

- [ ] Train / test split based on primary domain frequency
- [ ] Process multiple datasets
- [ ] Label data based on known malicious domains
