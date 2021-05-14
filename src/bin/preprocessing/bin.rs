#[macro_use]
extern crate clap;

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::time::Instant;

use clap::App;
use linereader::LineReader;

use thesis_data_pipeline::cli::create_cli_file;
use thesis_data_pipeline::parse_dns::parse_dns;
use thesis_data_pipeline::parse_log::parse_log_line;
use thesis_data_pipeline::shared_interface::{LogRecord, PrimaryDomainStats};

fn parse_opts() -> (File, File) {
    let yml = load_yaml!("cli_args.yaml");
    let m = App::from_yaml(yml).get_matches();

    let out_records = create_cli_file(m.value_of("out_records"), "out_records");
    let out_prim_stats = create_cli_file(m.value_of("out_prim_stats"), "out_prim_stats");

    (out_records, out_prim_stats)
}

const ASCII_TAB: u8 = b'\t';

fn main() -> Result<(), Box<dyn std::error::Error>> {
    print!("======================\n[THESIS] Data Pipeline\n======================\n\n-> Preprocessing\n   [1.] Working... ");

    let (out_records, out_prim_stats) = parse_opts();

    // Initialize counters
    let mut id: u32 = 0;
    let mut prim_id_counter: u32 = 0;

    // Primary domain <--> (id, length, count)
    let mut prim_map: HashMap<Vec<u8>, PrimaryDomainStats> = HashMap::new();

    // Initialize stdin reader
    let stdin = std::io::stdin();
    let stdin_lock = stdin.lock();
    let mut reader = LineReader::new(stdin_lock);

    // Initialize file writers
    let mut record_writer = BufWriter::new(out_records);
    let mut prim_stats_writer = BufWriter::new(out_prim_stats);

    let start_time = Instant::now();

    let mut line_counter: usize = 0;

    // Read input line-by-line
    while let Some(Ok(line)) = reader.next_line() {
        line_counter += 1;

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
    println!("   Input entries:    {}", line_counter);
    println!("   After processing: {}", id);
    println!("   Unique domains:   {}", prim_id_counter);
    println!();

    Ok(())
}
