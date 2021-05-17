use std::fmt;
use std::fs::{File, OpenOptions};
use std::path::PathBuf;

use dialoguer::Confirm;
use dialoguer::theme::ColorfulTheme;
use indicatif::{ProgressBar, ProgressStyle};

#[derive(Debug)]
pub enum CliError {
    MissingInputArg(String),
    InvalidArgument(String, String),
    FileNotFound(String),
    FileIsDirectory(String),
    FileExists(String),
    IO(String, std::io::Error),
}

impl std::error::Error for CliError {}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &*self {
            CliError::MissingInputArg(arg) => write!(f, "Missing input argument: {}.", arg),
            CliError::InvalidArgument(arg, msg) => write!(f, "Invalid input for argument \"{}\": {}.", arg, msg),
            CliError::FileNotFound(arg) => write!(f, "Could not find file \"{}\".", arg),
            CliError::FileIsDirectory(arg) => write!(f, "Provided file \"{}\" is a directory.", arg),
            CliError::FileExists(arg) => write!(f, "File \"{}\" already exists.", arg),
            CliError::IO(arg, err) => write!(f, "I/O error for {}: {}.", arg, err),
        }
    }
}

pub fn parse_output_file(input: &str, force_overwrite: bool) -> Result<File, CliError> {
    let path = PathBuf::from(input);

    if path.is_dir() {
        Err(CliError::FileIsDirectory(input.to_string()))
    } else if path.exists() && !force_overwrite {
        //
        match Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt(format!("File \"{}\" exists, overwrite?", input))
            .default(false).wait_for_newline(true).interact_opt()
        {
            Ok(Some(true)) => match OpenOptions::new().write(true).truncate(true).open(&path) {
                Ok(file) => Ok(file),
                Err(io_err) => Err(CliError::IO(input.to_string(), io_err))
            },
            _ => Err(CliError::FileExists(input.to_string()))
        }
    } else {
        match File::create(path) {
            Ok(file) => Ok(file),
            Err(io_err) => Err(CliError::IO(input.to_string(), io_err))
        }
    }
}

pub fn parse_input_file(input: &str) -> Result<File, CliError> {
    let path = PathBuf::from(input);

    if !path.exists() {
        Err(CliError::FileNotFound(input.to_string()))
    } else if path.is_dir() {
        Err(CliError::FileIsDirectory(input.to_string()))
    } else {
        match File::open(path) {
            Ok(file) => Ok(file),
            Err(io_err) => Err(CliError::IO(input.to_string(), io_err))
        }
    }
}

pub fn exit_with_error(e: Box<dyn std::error::Error>) -> ! {
    eprintln!("Error: {}", e);
    std::process::exit(1)
}

pub fn print_output(what: String, quiet: bool) {
    if quiet { return; }
    eprint!("{}", what);
}

pub fn make_progress_bar(size: u64, quiet: bool) -> Option<ProgressBar> {
    if quiet { return None; }
    let pb = ProgressBar::new(size);
    pb.set_draw_rate(5);
    pb.set_style(ProgressStyle::default_bar()
        .template("[{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} ({eta})")
        .progress_chars("#>-"));
    Some(pb)
}
