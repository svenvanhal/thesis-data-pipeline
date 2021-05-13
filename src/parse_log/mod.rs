mod hex;

#[derive(Debug)]
pub enum ParseLineError {
    SepNotFound,
    InvalidTimestamp,
    InvalidQuery,
}

const R_BYTE: u8 = b'\r';
const N_BYTE: u8 = b'\n';

/// Parse a line of bytes and return the timestamp as f64 and query as &str.
/// Expects the input in the form {TS}{TAB}{QUERY}{NEWLINE}, will NOT check for validity.
/// TODO: maybe check first line for validation
pub fn parse_log_line(line: &[u8], sep: u8) -> Result<(f64, Vec<u8>), ParseLineError> {

    // Find location of separator (and check that there exists data after separator)
    let sep_index = match line.iter().position(|&c| c == sep) {
        Some(idx) if line.len() > idx => idx,
        _ => return Err(ParseLineError::SepNotFound)
    };

    let ts_slice = &line[..sep_index];
    let mut q_slice = &line[(sep_index + 1)..];

    // Trim \n or \r\n
    q_slice = match q_slice.last() {
        Some(byte) if byte == &N_BYTE => &q_slice[..q_slice.len() - 1],
        _ => return Err(ParseLineError::InvalidQuery), // Query nor newline
    };
    if q_slice.last() == Some(&R_BYTE) { q_slice = &q_slice[..q_slice.len() - 1] };

    // Parse timestamp as (finite) f64 and decode byte escapes in query
    match fast_float::parse::<f64, _>(ts_slice) {
        Ok(ts) if ts.is_finite() => match hex::decode_byte_escapes(q_slice) {
            Some(query) => Ok((ts, query)),
            None => Err(ParseLineError::InvalidQuery)
        }
        _ => Err(ParseLineError::InvalidTimestamp)
    }
}


#[cfg(test)]
mod tests {
    use crate::parse_log::parse_log_line;

    #[test]
    fn test_parse_log_line() {
        let (ts, q) = parse_log_line(b"0	a\n", b'\t').unwrap();
        assert_eq!(ts, 0.);
        assert_eq!(q, vec![b'a']);
    }

    #[test]
    fn test_parse_log_line_no_linefeed() {
        assert!(parse_log_line(b"0	a", b'\t').is_err());
    }

    #[test]
    fn test_parse_log_line_rn() {
        let (ts, q) = parse_log_line(b"0	a\r\n", b'\t').unwrap();
        assert_eq!(ts, 0.);
        assert_eq!(q, vec![b'a']);
    }

    #[test]
    fn test_parse_log_line_byte_encoded_r() {
        let (ts, q) = parse_log_line(b"0	a\\x0d\n", b'\t').unwrap();
        assert_eq!(ts, 0.);
        assert_eq!(q, vec![b'a', b'\r']);
    }

    #[test]
    fn test_parse_log_line_byte_encoded_n() {
        let (ts, q) = parse_log_line(b"0	a\\x0a\n", b'\t').unwrap();
        assert_eq!(ts, 0.);
        assert_eq!(q, vec![b'a', b'\n']);
    }

    #[test]
    fn test_parse_log_line_hex() {
        let (ts, q) = parse_log_line(b"0	a\\xff\n", b'\t').unwrap();
        assert_eq!(ts, 0.);
        assert_eq!(q, vec![b'a', 255]);
    }

    #[test]
    fn test_parse_log_line_hex_accent() {
        let (ts, q) = parse_log_line(b"0	ex\xc3\xa4mple.com\n", b'\t').unwrap();
        assert_eq!(ts, 0.);
        assert_eq!(q, vec![b'e', b'x', b'\xc3', b'\xa4', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm']);
    }
}
