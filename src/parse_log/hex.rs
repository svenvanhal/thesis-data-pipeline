const HEX_SLASH: u8 = b'\\';
const HEX_X: u8 = b'x';

pub fn decode_byte_escapes(input_slice: &[u8]) -> Option<Vec<u8>> {

    // Pre-emptively check if slash in string, if not, just return owned vector
    // Upside of this approach is that most queries processed have no escaped bytes, so faster than iterative copying
    // Downside is extra iteration over input
    if !input_slice.contains(&HEX_SLASH) {
        return Some(input_slice.to_owned());
    }

    // Decode hex
    let mut result: Vec<u8> = Vec::with_capacity(input_slice.len());
    let mut it = input_slice.iter();

    while let Some(ch) = it.next() {
        if ch != &HEX_SLASH {
            result.push(*ch);
            continue;
        }

        if it.next() == Some(&HEX_X) {
            match (it.next(), it.next()) {
                (Some(a), Some(b)) => {
                    // Potentially valid byte escape
                    match parse_hex(a, b) {
                        Some(hex) => result.push(hex),
                        None => {
                            result.push(HEX_SLASH);
                            result.push(HEX_X);
                            result.push(*a);
                            result.push(*b);
                        }
                    }
                }
                (Some(a), None) => {
                    result.push(HEX_SLASH);
                    result.push(HEX_X);
                    result.push(*a);
                }
                _ => {
                    result.push(HEX_SLASH);
                    result.push(HEX_X);
                }
            }
        } else {
            result.push(HEX_SLASH);
        }
    }

    Some(result)
}

fn parse_hex(a: &u8, b: &u8) -> Option<u8> {
    match (byte_to_hex(a), byte_to_hex(b)) {
        (Some(first), Some(second)) => Some(16 * first + second),
        _ => None
    }
}

fn byte_to_hex(byte: &u8) -> Option<u8> {
    match byte {
        b'a'..=b'f' => Some(10 + (byte - b'a')),
        b'A'..=b'F' => Some(10 + (byte - b'A')),
        b'0'..=b'9' => Some(byte - b'0'),
        _ => None
    }
}

#[cfg(test)]
mod tests {
    use crate::parse_log::hex::{byte_to_hex, parse_hex, decode_byte_escapes};

    #[test]
    fn test_decode_byte_escapes_valid() {
        let test_str = br"\x54\x48\x45\x53\x49\x53\x4c\x49\x46\x45".to_vec();
        let expected = b"THESISLIFE".to_vec();

        assert_eq!(expected, decode_byte_escapes(&test_str).unwrap());
    }

    #[test]
    fn test_decode_byte_escapes_invalid() {
        let test_01 = b"".to_vec();
        let test_02 = br"\".to_vec();
        let test_03 = br"\x".to_vec();
        let test_04 = br"\xA".to_vec();
        let test_05 = br"\xGG".to_vec();
        let test_06 = b"noHex".to_vec();

        // Invalid escapes just pass through
        assert_eq!(test_01, decode_byte_escapes(&test_01).unwrap());
        assert_eq!(test_02, decode_byte_escapes(&test_02).unwrap());
        assert_eq!(test_03, decode_byte_escapes(&test_03).unwrap());
        assert_eq!(test_04, decode_byte_escapes(&test_04).unwrap());
        assert_eq!(test_05, decode_byte_escapes(&test_05).unwrap());
        assert_eq!(test_06, decode_byte_escapes(&test_06).unwrap());
    }

    #[test]
    fn test_parse_hex() {
        assert_eq!(0, parse_hex(&b'0', &b'0').unwrap());

        assert_eq!(26, parse_hex(&b'1', &b'a').unwrap());
        assert_eq!(26, parse_hex(&b'1', &b'A').unwrap());

        assert_eq!(161, parse_hex(&b'a', &b'1').unwrap());
        assert_eq!(161, parse_hex(&b'A', &b'1').unwrap());

        assert_eq!(255, parse_hex(&b'F', &b'F').unwrap());

        assert!(parse_hex(&b'G', &b'G').is_none());
    }

    #[test]
    fn test_byte_to_hex_valid() {
        let result_lower: Vec<u8> = b"abcdef".iter().map(|b| byte_to_hex(b).unwrap()).collect();
        let result_upper: Vec<u8> = b"ABCDEF".iter().map(|b| byte_to_hex(b).unwrap()).collect();
        let result_digits: Vec<u8> = b"0123456789".iter().map(|b| byte_to_hex(b).unwrap()).collect();

        assert_eq!(vec![10, 11, 12, 13, 14, 15], result_lower);
        assert_eq!(vec![10, 11, 12, 13, 14, 15], result_upper);
        assert_eq!(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9], result_digits);
    }

    #[test]
    fn test_byte_to_hex_invalid() {
        let invalids: Vec<Option<u8>> = b"GZ\\\xEB\xE1_\x00".iter().map(|b| byte_to_hex(b)).collect();

        for invalid in invalids {
            assert!(invalid.is_none());
        }
    }
}