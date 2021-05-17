#[macro_use]
extern crate clap;

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Write, BufReader};
use std::time::Instant;

use clap::App;
use linereader::LineReader;

use thesis_data_pipeline::parse_dns::parse_dns;
use thesis_data_pipeline::parse_log::parse_log_line;
use thesis_data_pipeline::shared_interface::{LogRecord, PrimaryDomainStats};
use std::path::PathBuf;
use thesis_data_pipeline::cli;
use indicatif::ProgressBar;

fn parse_opts() -> (File, File, File) {
    let yml = load_yaml!("cli_args.yaml");
    let m = App::from_yaml(yml).get_matches();

    let in_file = match m.value_of("out_records") {
        Some(path) => match cli::parse_input_file(PathBuf::from(path)) {
            Ok(file) => file,
            Err(err) => cli::exit_with_error(err.into())
        }
        None => cli::exit_with_error(cli::CliError::MissingInputArg(String::from("[input file]")).into())
    };

    let out_records = match m.value_of("out_records") {
        Some(path) => match cli::parse_output_file(PathBuf::from(path)) {
            Ok(file) => file,
            Err(err) => cli::exit_with_error(err.into())
        }
        None => cli::exit_with_error(cli::CliError::MissingInputArg(String::from("--out-records")).into())
    };

    let out_prim_stats = match m.value_of("out_prim_stats") {
        Some(path) => match cli::parse_output_file(PathBuf::from(path)) {
            Ok(file) => file,
            Err(err) => cli::exit_with_error(err.into())
        }
        None => cli::exit_with_error(cli::CliError::MissingInputArg(String::from("--out-prim")).into())
    };

    (in_file, out_records, out_prim_stats)
}

const ASCII_TAB: u8 = b'\t';

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (in_file, out_records, out_prim_stats) = parse_opts();

    // Initialize counters
    let mut id: u32 = 0;
    let mut prim_id_counter: u32 = 0;

    // Primary domain <--> (id, length, count)
    let mut prim_map: HashMap<Vec<u8>, PrimaryDomainStats> = HashMap::new();

    // Count lines in file for progress bar
    let lc = match linecount::count_lines(&in_file) {
        Ok(count) => count,
        Err(e) => cli::exit_with_error(e.into())
    };

    // Initialize file reader
    let mut reader = LineReader::new(BufReader::new(in_file));

    // Initialize file writers
    let mut record_writer = BufWriter::new(out_records);
    let mut prim_stats_writer = BufWriter::new(out_prim_stats);

    // Initialize progress bar
    let pb = ProgressBar::new(lc as u64);

    let start_time = Instant::now();

    let mut read_counter: usize = 0;

    // Read input line-by-line
    while let Some(Ok(line)) = reader.next_line() {
        read_counter += 1;

        // Parse log line
        if let Ok((ts, query)) = parse_log_line(&line, ASCII_TAB) {

            // TODO: parse negative/invalid ts?
            // if ts < 0. { return Err(ParseDnsError::NegTimestamp); }

            // Parse DNS payload
            if let Ok((primary_domain, payload)) = parse_dns(&query) {
                let prim_len = primary_domain.len() as u8;

                // Get or insert primary domain stats entry
                let prim_entry = prim_map.entry(primary_domain).or_insert_with(|| {
                    let current_prim_id = prim_id_counter;
                    prim_id_counter += 1;

                    PrimaryDomainStats { id: current_prim_id, length: prim_len, count: 0 }
                });

                // Create output record
                let row_data = LogRecord { id, prim_id: prim_entry.id, ts, payload };

                // Write output record
                bincode::serialize_into(&mut record_writer, &row_data)?;

                // Increase counts for prim and queries
                prim_entry.count += 1;
                id += 1;
            }
        }

        pb.inc(1);
    }

    record_writer.flush()?;
    drop(record_writer);

    // Write primary domain stats to output as well
    for stats_entry in prim_map.values() {
        bincode::serialize_into(&mut prim_stats_writer, stats_entry)?;
    }

    prim_stats_writer.flush()?;
    drop(prim_stats_writer);

    println!(" done! Time elapsed: {:.1?}\n", start_time.elapsed());
    println!("   Input entries:    {}", read_counter);
    println!("   After processing: {}", id);
    println!("   Unique domains:   {}\n", prim_id_counter);

    Ok(())
}
