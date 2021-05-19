#[macro_use]
extern crate clap;

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use clap::App;
use csv::QuoteStyle;
use dialoguer::console::{Emoji, style};
use flate2::Compression;
use flate2::write::GzEncoder;
use rayon::iter::{IntoParallelIterator, ParallelIterator};

use thesis_data_pipeline::cli;
use thesis_data_pipeline::feature_extraction::{extract_features_per_domain, ExtractOpts};
use thesis_data_pipeline::shared_interface::{LogRecord, PrimaryDomainStats, SerializedLogEntry};

// Key for both maps is primary domain ID
type QueryMap = HashMap<u32, Vec<LogRecord>>;
type PrimStats = HashMap<u32, PrimaryDomainStats>;

static LOADING: Emoji<'_, '_> = Emoji("⏳ ", "");
static WORKING: Emoji<'_, '_> = Emoji("🛠️ ", "");
static SPARKLE: Emoji<'_, '_> = Emoji("✨ ", "");

#[derive(Debug)]
pub struct Opts {
    pub extract_opts: ExtractOpts,
    pub in_records: File,
    pub in_prim: File,
    pub out_features: File,
    quiet: bool,
}

fn parse_opts() -> Opts {
    let yml = load_yaml!("cli_args.yaml");
    let m = App::from_yaml(yml).get_matches();

    let quiet = m.is_present("quiet");

    // Parse and validate feature extraction arguments
    let extract_opts = ExtractOpts {
        payload: m.is_present("payload"),

        time: if m.is_present("time") {
            let duration = value_t_or_exit!(m, "time", f32);
            if duration <= 0. {
                let err = Box::new(cli::CliError::InvalidArgument(String::from("-t/--time"), String::from("window duration too short")));
                cli::exit_with_error(err)
            }
            Some(duration)
        } else { None },

        fixed: if m.is_present("fixed") {
            let size = value_t_or_exit!(m, "fixed", usize);
            if size == 0 {
                let err = Box::new(cli::CliError::InvalidArgument(String::from("-f/--fixed"), String::from("window size too small")));
                cli::exit_with_error(err)
            }
            Some(size)
        } else { None },
    };

    // Parse and validate input/output file arguments
    let in_records = match m.value_of("in_records") {
        Some(input) => match cli::parse_input_file(input) {
            Ok(file) => file,
            Err(err) => cli::exit_with_error(Box::new(err))
        }
        None => {
            let err = Box::new(cli::CliError::MissingInputArg(String::from("--in-records")));
            cli::exit_with_error(err)
        }
    };

    let in_prim = match m.value_of("in_prim") {
        Some(input) => match cli::parse_input_file(input) {
            Ok(file) => file,
            Err(err) => cli::exit_with_error(Box::new(err))
        }
        None => {
            let err = Box::new(cli::CliError::MissingInputArg(String::from("--in-prim")));
            cli::exit_with_error(err)
        }
    };

    let out_features = match m.value_of("out_features") {
        Some(input) => match cli::parse_output_file(input, quiet) {
            Ok(file) => file,
            Err(err) => cli::exit_with_error(Box::new(err))
        }
        None => {
            let err = Box::new(cli::CliError::MissingInputArg(String::from("<out_features>")));
            cli::exit_with_error(err)
        }
    };

    Opts { extract_opts, in_records, in_prim, out_features, quiet }
}

fn consume_input(opts: &Opts) -> (QueryMap, PrimStats, u64) {
    cli::print_output(format!("\n{}   {}Loading filtered entries...\n", style("[1/2]").bold().dim(), LOADING), opts.quiet);

    // Load primary domain stats
    let mut prim_stats: HashMap<u32, PrimaryDomainStats> = HashMap::new();
    let mut n_entries: u64 = 0;

    let mut stats_reader = BufReader::new(&opts.in_prim);
    while let Ok(stats) = bincode::deserialize_from::<_, PrimaryDomainStats>(&mut stats_reader) {
        n_entries += stats.count as u64;
        prim_stats.insert(stats.id, stats);
    }

    let pb = cli::make_progress_bar(n_entries, opts.quiet);

    // Map for loaded queries. prim_id <--> (prim_len, [DnsEntry..])
    let mut queries: QueryMap = HashMap::with_capacity(prim_stats.len());

    // Load records
    let mut record_reader = BufReader::new(&opts.in_records);
    while let Ok((prim_id, log_record)) = bincode::deserialize_from::<_, SerializedLogEntry>(&mut record_reader) {

        // Get or create bucket for primary domain, using known capacity for efficiency
        let bucket = queries.entry(prim_id).or_insert_with(|| {
            let prim_capacity = prim_stats[&prim_id].count as usize;
            Vec::with_capacity(prim_capacity)
        });

        // Insert query in map
        bucket.push(log_record);

        // Update progress bar
        if Option::is_some(&pb) { pb.as_ref().unwrap().inc(1); }
    }
    if Option::is_some(&pb) { pb.as_ref().unwrap().finish(); }

    // TODO: warn and exit if n_entries is not the same as lines read

    (queries, prim_stats, n_entries)
}

fn extract_features(file: &File, opts: &Opts, queries: QueryMap, prim_stats: &HashMap<u32, PrimaryDomainStats>, n_entries: u64) {
    cli::print_output(format!("\n{}   {}Extracting features...\n", style("[2/2]").bold().dim(), WORKING), opts.quiet);

    let pb = Arc::new(Mutex::new(cli::make_progress_bar(n_entries, opts.quiet)));

    // Create CSV writer (with Arc and Mutex for thread sharing)
    let gz_writer = GzEncoder::new(BufWriter::new(file), Compression::fast());
    let csv_writer = Arc::new(Mutex::new(csv::WriterBuilder::new()
        .flexible(true) // faster, no checking
        .quote_style(QuoteStyle::Never)
        .from_writer(gz_writer)));

    // Process queries
    let features = queries.into_par_iter()
        .map(|(prim_id, mut entries)| {
            // Check for empty entry vec, so unwrap when ordering below is safe
            if entries.is_empty() { return Vec::new(); }

            // Sort entries by timestamp
            entries.sort_by(|a, b| a.ts.partial_cmp(&b.ts).unwrap());

            // Extract features
            let prim = &prim_stats[&prim_id];
            let features = extract_features_per_domain(&opts.extract_opts, entries, prim.length);

            // Write to output file from thread for 1000 vectors or more (performance improvement, empirically determined)
            let ret_val = if prim.count >= 1000 {
                let mut w = csv_writer.lock().unwrap();
                features.iter().for_each(|fv| if let Err(e) = w.serialize(fv) {
                    cli::exit_with_error(Box::new(e));
                });
                Vec::new()
            } else { features };

            // Update progress bar (soft fail on error)
            if let Ok(pb_lock) = pb.lock() {
                if Option::is_some(&pb_lock) { pb_lock.as_ref().unwrap().inc(prim.count as u64); }
            }

            ret_val
        })
        .flatten().collect::<Vec<_>>();

    // Finalize progress bar (soft fail on error)
    if let Ok(pb_lock) = pb.lock() {
        if Option::is_some(&pb_lock) { pb_lock.as_ref().unwrap().finish(); }
    }

    // Write remaining feature vectors to file
    let mut w = csv_writer.lock().unwrap();
    features.iter().for_each(|fv| if let Err(e) = w.serialize(fv) {
        cli::exit_with_error(Box::new(e));
    });

    if let Err(e) = w.flush() {
        cli::exit_with_error(Box::new(e));
    }
}

fn main() {
    let opts = parse_opts();

    // Load input data
    let start = Instant::now();
    let (queries, prim_stats, n_entries) = consume_input(&opts);

    // Extract features
    extract_features(&opts.out_features, &opts, queries, &prim_stats, n_entries);

    // Print total duration
    eprintln!("\n        {}Finished in {:.1?}", SPARKLE, start.elapsed());
}
