use std::fs::{File, OpenOptions};
use std::path::PathBuf;
use dialoguer::theme::ColorfulTheme;
use dialoguer::Confirm;
use std::fmt;

#[derive(Debug)]
pub enum CliError {
    MissingInputArg(String),
    FileNotFound,
    FileIsDirectory,
    FileExists,
    IO(std::io::Error),
}

impl std::error::Error for CliError {}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &*self {
            CliError::MissingInputArg(arg) => write!(f, "Missing input argument: {}.", arg),
            CliError::FileNotFound => write!(f, "Could not find file."),
            CliError::FileIsDirectory => write!(f, "Provided file is a directory."),
            CliError::FileExists => write!(f, "File already exists."),
            CliError::IO(err) => write!(f, "I/O error: {}.", err),
        }
    }
}

// impl Into<Box<CliError>> for CliError {
//     fn into(self) -> Box<CliError> {
//         Box::new(self)
//     }
// }

pub fn parse_output_file(path: PathBuf) -> Result<File, CliError> {
    if path.is_dir() {
        Err(CliError::FileIsDirectory)
    } else if path.exists() {
        //
        match Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("File \"{}\" exists, overwrite?")
            .default(false).interact_opt()
        {
            Ok(Some(true)) => match OpenOptions::new().read(true).write(true).truncate(true).open(&path) {
                Ok(file) => Ok(file),
                Err(io_err) => Err(CliError::IO(io_err))
            },
            _ => Err(CliError::FileExists)
        }
    } else {
        match File::create(path) {
            Ok(file) => Ok(file),
            Err(io_err) => Err(CliError::IO(io_err))
        }
    }
}

pub fn parse_input_file(path: PathBuf) -> Result<File, CliError> {
    if !path.exists() {
        Err(CliError::FileNotFound)
    } else if path.is_dir() {
        Err(CliError::FileIsDirectory)
    } else {
        match File::create(path) {
            Ok(file) => Ok(file),
            Err(err) => Err(CliError::IO(err))
        }
    }
}

pub fn exit_with_error(e: Box<dyn std::error::Error>) -> ! {
    eprintln!("Error: {}", e);
    std::process::exit(1)
}
