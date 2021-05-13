use std::fs::File;
use std::path::PathBuf;

pub fn create_cli_file(cli_arg: Option<&str>, name: &str) -> File {
    let path = match cli_arg {
        Some(path) => PathBuf::from(path),
        None => panic!("[{}] Missing argument.", name)
    };

    if path.is_dir() {
        panic!("[{}] Path is directory: {:?}", name, path);
    } else if path.exists() {
        panic!("[{}] File already exists: {:?}", name, path);
    }

    // Create file
    match File::create(path) {
        Ok(file) => file,
        Err(e) => panic!("[{}] Could not create file: {}", name, e)
    }
}
