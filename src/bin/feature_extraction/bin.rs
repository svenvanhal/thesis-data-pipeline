#[macro_use]
extern crate clap;

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use clap::App;
use csv::QuoteStyle;
use flate2::Compression;
use flate2::write::GzEncoder;
use rayon::iter::{IntoParallelIterator, ParallelIterator};

use thesis_data_pipeline::cli::create_cli_file;
use thesis_data_pipeline::feature_extraction::{extract_features_per_domain, ExtractOpts};
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
            if size == 0 { panic!("Provided fixed window size is too short."); }
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

fn extract_features(file: &File, opts: &ExtractOpts, queries: QueryMap, prim_stats: &HashMap<u32, PrimaryDomainStats>) {

    // Create CSV writer (with Arc and Mutex for thread sharing)
    let gz_writer = GzEncoder::new(BufWriter::new(file), Compression::fast());

    let csv_writer = Arc::new(Mutex::new(csv::WriterBuilder::new()
        .has_headers(false) // TODO: find a solution for feature names
        .quote_style(QuoteStyle::Never)
        .from_writer(gz_writer)));

    // Process queries
    let features = queries.into_par_iter()
        .map(|(prim_id, mut entries)| {
            let prim = &prim_stats[&prim_id];

            // Sort entries by timestamp (first item (.0) in tuple is timestamp)
            entries.sort_by(|a, b| (&a.0).partial_cmp(&b.0).unwrap());

            // Extract features
            let features = extract_features_per_domain(&opts, entries, prim.length);

            // Don't write less than 1000 queries to reduce locking overhead (empirically determined)
            if prim.count > 1000 {

                // Lock writer and write features
                let mut w = csv_writer.lock().unwrap();
                features.into_iter().for_each(|fv| {
                    w.serialize(fv).expect("Could not write feature vector to file.");
                });

                Vec::new()
            } else { features }
        })
        .flatten()
        .collect::<Vec<_>>();

    // Write remaining feature vectors to file
    let mut w = csv_writer.lock().unwrap();
    features.iter().for_each(|fv| {
        w.serialize(fv).expect("Could not write feature vector to file.");
    });
    w.flush().expect("Could not flush CSV writer.");
}

fn main() {
    print!("======================\n[THESIS] Data Pipeline\n======================\n\n-> Feature Extraction\n   [1.] Loading data...        ");

    // Parse CLI arguments
    let opts = parse_opts();

    // Load input data
    let start = Instant::now();
    let (queries, prim_stats) = consume_input(&opts);
    println!("done! Time elapsed: {:.1?}", start.elapsed());

    let time = Instant::now();

    // Extract features
    print!("   [2.] Extracting features... ");
    extract_features(&opts.out_features, &opts.extract_opts, queries, &prim_stats);
    println!("done! Time elapsed: {:.1?}", time.elapsed());

    // Print total duration
    println!("\n   Total duration: {:.1?}\n", start.elapsed());
}
