#[macro_use]
extern crate clap;

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, BufWriter, Seek, SeekFrom, Write};
use std::time::Instant;

use clap::App;
use dialoguer::console::{Emoji, style};
use linereader::LineReader;
use num_format::{Locale, ToFormattedString};

use thesis_data_pipeline::cli;
use thesis_data_pipeline::parse_dns::parse_dns;
use thesis_data_pipeline::parse_log::parse_log_line;
use thesis_data_pipeline::shared_interface::{LogRecord, PrimaryDomainStats, SerializedLogEntry};

const ASCII_TAB: u8 = b'\t';

static PAPER: Emoji<'_, '_> = Emoji("📃 ", "");
static SPARKLE: Emoji<'_, '_> = Emoji("✨ ", "");
static BAR_CHART: Emoji<'_, '_> = Emoji("📊 ", "");

struct Opts {
    in_file: File,
    out_records: File,
    out_prim: File,
    quiet: bool,
}

fn parse_opts() -> Opts {
    let yml = load_yaml!("cli_args.yaml");
    let m = App::from_yaml(yml).get_matches();

    let quiet = m.is_present("quiet");

    let in_file = match m.value_of("input_file") {
        Some(input) => match cli::parse_input_file(input) {
            Ok(file) => file,
            Err(err) => cli::exit_with_error(Box::new(err))
        }
        None => {
            let err = Box::new(cli::CliError::MissingInputArg(String::from("<input_file>")));
            cli::exit_with_error(err)
        }
    };

    let out_records = match m.value_of("out_records") {
        Some(input) => match cli::parse_output_file(input, quiet) {
            Ok(file) => file,
            Err(err) => cli::exit_with_error(Box::new(err))
        }
        None => {
            let err = Box::new(cli::CliError::MissingInputArg(String::from("--out-records")));
            cli::exit_with_error(err)
        }
    };

    let out_prim = match m.value_of("out_prim_stats") {
        Some(input) => match cli::parse_output_file(input, quiet) {
            Ok(file) => file,
            Err(err) => cli::exit_with_error(Box::new(err))
        }
        None => {
            let err = Box::new(cli::CliError::MissingInputArg(String::from("--out-prim")));
            cli::exit_with_error(err)
        }
    };

    Opts { in_file, out_records, out_prim, quiet }
}

/// TODO: filter fast retransmissions
fn main() {
    let opts = parse_opts();
    let start_time = Instant::now();

    // Primary domain <--> (id, length, count)
    let mut prim_map: HashMap<String, PrimaryDomainStats> = HashMap::new();

    // Count lines in file for progress bar (and seek to start for reprocessing)
    let time_count = Instant::now();
    let mut in_file = &opts.in_file;
    let lc = match linecount::count_lines(in_file) {
        Ok(count) => count,
        Err(e) => cli::exit_with_error(Box::new(e))
    };
    if let Err(e) = in_file.seek(SeekFrom::Start(0)) {
        cli::exit_with_error(Box::new(e));
    }

    cli::print_output(style(format!("\n           (Counted lines in {:.1?})\n\n", time_count.elapsed())).dim().to_string(), opts.quiet);
    cli::print_output(format!("{}   {}Processing log entries...\n", style("[1/2]").bold().dim(), PAPER), opts.quiet);

    // Make progress bar
    let pb = cli::make_progress_bar(lc as u64, opts.quiet);

    // Initialize file reader
    let mut reader = LineReader::new(BufReader::new(in_file));

    // Initialize file writers
    let mut record_writer = BufWriter::new(&opts.out_records);
    let mut prim_stats_writer = BufWriter::new(&opts.out_prim);

    // Initialize counters
    let mut id: usize = 0;
    let mut prim_id_counter: u32 = 0;

    // Read input line-by-line
    while let Some(Ok(line)) = reader.next_line() {

        // Parse log line
        if let Ok((ts, query)) = parse_log_line(&line, ASCII_TAB) {

            // FILTER: negative timestamp
            if ts < 0. { continue; }

            // Parse DNS payload
            if let Ok((primary_domain, payload)) = parse_dns(&query) {
                let prim_len = primary_domain.len() as u8;

                // Get or insert primary domain stats entry
                let prim_entry = prim_map.entry(primary_domain).or_insert_with(|| {
                    let current_prim_id = prim_id_counter;
                    prim_id_counter += 1;

                    PrimaryDomainStats { id: current_prim_id, length: prim_len, count: 0 }
                });

                // TODO: alternative to serialize_into as is creates a new serializer every loop

                // Create and output log record
                let row_data: SerializedLogEntry = (prim_entry.id, LogRecord { id, ts, payload });
                if let Err(e) = bincode::serialize_into(&mut record_writer, &row_data) {
                    cli::exit_with_error(Box::new(e));
                }

                // Increase counts for prim and queries
                prim_entry.count += 1;
                id += 1;
            }
        }

        if Option::is_some(&pb) { pb.as_ref().unwrap().inc(1); }
    }
    if Option::is_some(&pb) { pb.as_ref().unwrap().finish(); }

    if let Err(e) = record_writer.flush() {
        cli::exit_with_error(Box::new(e));
    }

    // Write primary domain stats to output as well
    cli::print_output(format!("\n{}   {}Exporting primary domain statistics... ", style("[2/2]").bold().dim(), BAR_CHART), opts.quiet);
    for stats_entry in prim_map.values() {
        if let Err(e) = bincode::serialize_into(&mut prim_stats_writer, stats_entry) {
            cli::exit_with_error(Box::new(e));
        }
    }
    if let Err(e) = prim_stats_writer.flush() {
        cli::exit_with_error(Box::new(e));
    }
    cli::print_output("Done!\n\n".to_string(), opts.quiet);

    eprintln!("           Input lines:     {}", lc.to_formatted_string(&Locale::en));
    eprintln!("           Output entries:  {}", id.to_formatted_string(&Locale::en));
    eprintln!("           Primary domains: {}\n", prim_id_counter.to_formatted_string(&Locale::en));
    eprintln!("        {}Finished in {:.1?}", SPARKLE, start_time.elapsed());
}
