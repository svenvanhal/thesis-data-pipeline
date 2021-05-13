#[macro_use]
extern crate clap;

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::time::Instant;

use clap::App;
use csv::QuoteStyle;
use rayon::iter::{IntoParallelIterator, ParallelIterator};

use thesis_data_pipeline::cli::create_cli_file;
use thesis_data_pipeline::feature_extraction::{extract_features_per_domain, ExtractOpts, FeatureRow};
use thesis_data_pipeline::parse_dns::DnsPayload;
use thesis_data_pipeline::shared_interface::{LogRecord, PrimaryDomainStats};

type QueryMap = HashMap<u32, Vec<(f64, DnsPayload)>>;

#[derive(Debug)]
pub struct Opts {
    pub extract_opts: ExtractOpts,
    pub in_records: File,
    pub in_prim_stats: File,
    pub out_features: File,
}

fn parse_opts() -> Opts {
    // Define app arguments and parse input
    let yml = load_yaml!("cli_args.yaml");
    let m = App::from_yaml(yml).get_matches();

    // Parse and validate arguments
    let feature_extract_opts = ExtractOpts {
        payload: m.is_present("payload"),
        time: if m.is_present("time") {
            let duration = value_t_or_exit!(m, "time", f32);
            if duration <= 0. { panic!("Provided time window duration is too short."); }
            Some(duration)
        } else { None },
        fixed: if m.is_present("fixed") {
            let size = value_t_or_exit!(m, "fixed", usize);
            if size <= 0 { panic!("Provided fixed window size is too short."); }
            Some(size)
        } else { None },
    };

    Opts {
        extract_opts: feature_extract_opts,
        in_records: match m.value_of("in_records") {
            None => panic!("No input records provided."),
            Some(path) => File::open(path).expect("Cannot open input records file.")
        },
        in_prim_stats: match m.value_of("in_prim_stats") {
            None => panic!("No input primary domain stats provided."),
            Some(path) => File::open(path).expect("Cannot open input primary domain stats file.")
        },
        out_features: create_cli_file(m.value_of("out_features"), "out_features"),
    }
}

fn consume_input(opts: &Opts) -> (QueryMap, HashMap<u32, PrimaryDomainStats>) {

    // Load primary domain stats
    let mut prim_stats: HashMap<u32, PrimaryDomainStats> = HashMap::new();

    let mut stats_reader = BufReader::new(&opts.in_prim_stats);
    while let Ok(stats) = bincode::deserialize_from::<_, PrimaryDomainStats>(&mut stats_reader) {
        prim_stats.insert(stats.id, stats);
    }

    // Query map to extract features from. Initialize with known size to prevent reallocations.
    // prim_id <--> (prim_len, [DnsEntry..])
    let mut queries: QueryMap = HashMap::with_capacity(prim_stats.len());

    let mut record_reader = BufReader::new(&opts.in_records);

    // Load records
    while let Ok(result) = bincode::deserialize_from::<_, LogRecord>(&mut record_reader) {

        // Get or create bucket for primary domain, using known capacity for efficiency
        let bucket = queries.entry(result.prim_id).or_insert_with(|| {
            let prim_capacity = prim_stats[&result.prim_id].count as usize;
            Vec::with_capacity(prim_capacity)
        });

        // Insert query in map
        bucket.push((result.ts, result.payload));
    }

    (queries, prim_stats)
}

fn extract_features(opts: &ExtractOpts, queries: QueryMap, prim_stats: &HashMap<u32, PrimaryDomainStats>) -> Vec<FeatureRow> {
    queries.into_par_iter()
        .map(|(prim_id, mut entries)| {
            let prim_len = prim_stats[&prim_id].length;

            // Sort entries by timestamp (first item (.0) in tuple is timestamp)
            entries.sort_by(|a, b| (&a.0).partial_cmp(&b.0).unwrap());
            extract_features_per_domain(&opts, entries, prim_len)
        })
        .flatten()
        .collect::<Vec<FeatureRow>>()
}

fn write_to_file(file: &File, features: Vec<FeatureRow>) {
    let w = BufWriter::new(file);

    let mut csv_writer = csv::WriterBuilder::new()
        .has_headers(false) // TODO: find a solution for dynamic headers
        .quote_style(QuoteStyle::Never)
        .from_writer(w);

    features.into_iter().for_each(|fv: FeatureRow| {
        csv_writer.serialize(fv).expect("Could not write feature vector to file.");
    });

    csv_writer.flush().expect("Error: Could not flush writer.");
}

fn main() {
    println!("======================\n[THESIS] Data Pipeline\n======================\n  -> Feature Extraction\n\n  [-] Loading data...");

    // Parse CLI arguments
    let opts = parse_opts();

    // Load input data
    let mut time = Instant::now();
    let (queries, prim_stats) = consume_input(&opts);
    println!("  [-] Done! Time elapsed: {:.1?}", time.elapsed());

    time = Instant::now();

    // Extract features
    println!("  [-] Extracting features...");
    let features = extract_features(&opts.extract_opts, queries, &prim_stats);
    println!("  [-] Done! Time elapsed: {:.1?}", time.elapsed());

    time = Instant::now();

    // Write to file
    println!("  [-] Writing to file...");
    write_to_file(&opts.out_features, features);
    println!("  [-] Done! Time elapsed: {:.1?}", time.elapsed());
}
