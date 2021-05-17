use std::fmt;
use std::fs::{File, OpenOptions};
use std::path::PathBuf;

use dialoguer::Confirm;
use dialoguer::theme::ColorfulTheme;

#[derive(Debug)]
pub enum CliError {
    MissingInputArg(String),
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
            CliError::FileNotFound(arg) => write!(f, "Could not find file \"{}\".", arg),
            CliError::FileIsDirectory(arg) => write!(f, "Provided file \"{}\" is a directory.", arg),
            CliError::FileExists(arg) => write!(f, "File \"{}\" already exists.", arg),
            CliError::IO(arg, err) => write!(f, "I/O error for {}: {}.", arg, err),
        }
    }
}

pub fn parse_output_file(input: &str) -> Result<File, CliError> {
    let path = PathBuf::from(input);

    if path.is_dir() {
        Err(CliError::FileIsDirectory(input.to_string()))
    } else if path.exists() {
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
