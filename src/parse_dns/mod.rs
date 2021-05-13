use psl::{List, Psl};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, PartialEq)]
pub struct DnsPayload {
    pub labels: Vec<Vec<u8>>,
    pub payload_len: u8,
}

impl std::fmt::Debug for DnsPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "len={} {:#?}", self.payload_len, &self.labels)
    }
}

#[derive(Debug)]
pub enum ParseDnsError {
    QueryLength,
    InvalidDnsName,
    UnknownSuffix,
    NoLabels,
    InvalidPrim,
}

const LABEL_SEP: u8 = b'.';

/// Parse and validate/filter given byte vector as DNS query.
pub fn parse_dns(dns_query: &Vec<u8>) -> Result<(Vec<u8>, DnsPayload), ParseDnsError> {
    // TODO: thorough test suite

    // TODO: move out of this function
    // Prohibit negative timestamps and queries that cannot contain labels (at least len 5 --> a.b.c)
    //

    let q_len = dns_query.len();
    if q_len < 5 { return Err(ParseDnsError::QueryLength); }
    if q_len > 255 { return Err(ParseDnsError::InvalidDnsName); }

    // Parse domain name
    if let Some(domain) = List.domain(&dns_query) {
        let prim: Vec<u8> = domain.as_bytes().to_owned();

        // FILTER: known suffix
        if !domain.suffix().is_known() { return Err(ParseDnsError::UnknownSuffix); }

        // FILTER no labels (check 1)
        if q_len - prim.len() == 0 { return Err(ParseDnsError::NoLabels); }

        let labels_concat: &[u8] = dns_query.get(..q_len - prim.len() - 1).unwrap_or_default();

        // FILTER: no labels (check 2)
        if labels_concat.len() == 0 { return Err(ParseDnsError::NoLabels); }

        // TODO: filter invalid primary domain (with regex, noise)

        // Collect labels in vector
        let labels = labels_concat
            .split(|c: &u8| *c == LABEL_SEP)
            .map(|label| label.to_owned())
            .collect::<Vec<Vec<u8>>>();

        // FILTER: empty labels
        let mut payload_len: usize = 0;
        for label in labels.iter() {
            if label.is_empty() || label.len() > 63 { return Err(ParseDnsError::InvalidDnsName); }
            if label.is_empty() || label.len() > 63 { return Err(ParseDnsError::InvalidDnsName); }
            payload_len += label.len();
        }

        Ok((prim, DnsPayload {
            labels,
            payload_len: payload_len as u8,
        }))
    } else {
        // FILTER: invalid DNS name (could not be parsed)
        return Err(ParseDnsError::InvalidDnsName);
    }
}


#[cfg(test)]
mod tests {
    use crate::parse_dns::{DnsPayload, parse_dns};

    #[test]
    fn test_valid_domain() {
        let expected = DnsPayload {
            labels: vec!["label1".as_bytes().into(), "label2".as_bytes().into()],
            payload_len: 12,
        };

        let q = "label1.label2.example.com".as_bytes().into();
        let (_, result) = parse_dns(&q).unwrap();

        assert_eq!(expected, result)
    }

    #[test]
    fn filter_empty_query() {
        let empty = vec![];
        assert!(parse_dns(&empty).is_err())
    }

    #[test]
    fn filter_no_labels() {
        let no_label = b"example.com".to_vec().to_owned();
        assert!(parse_dns(&no_label).is_err());
    }

    #[test]
    fn filter_empty_label() {
        let empty_label = b".example.com".to_vec().to_owned();
        assert!(parse_dns(&empty_label).is_err());
    }

    #[test]
    fn filter_invalid_double_sep() {
        let double_sep_empty = b"..example.com".to_vec().to_owned();
        assert!(parse_dns(&double_sep_empty).is_err())
    }

    #[test]
    fn filter_invalid_double_sep_not_empty() {
        let double_sep_not_empty = b"test..test.example.com".to_vec().to_owned();
        assert!(parse_dns(&double_sep_not_empty).is_err())
    }

    #[test]
    fn filter_invalid_query_too_long() {
        let ll = "a".repeat(63);
        let too_long = format!("{}.{}.{}.{}.example.com", ll, ll, ll, ll);  // max = 253, this is (252 + |.example.com|)
        let too_long = too_long.as_bytes().to_owned();

        assert!(parse_dns(&too_long).is_err())
    }

    #[test]
    fn filter_invalid_label_too_long() {
        let ll = "a".repeat(70);
        let one_long_label = format!("{}.example.com", ll);
        let one_long_label = one_long_label.as_bytes().to_owned();

        assert!(parse_dns(&one_long_label).is_err())
    }

    #[test]
    fn filter_root_label() {
        let root_label = b".".to_vec().to_owned();
        assert!(parse_dns(&root_label).is_err())
    }

    #[test]
    fn filter_short_query_fast_path() {
        let short_query = b".a.b".to_vec().to_owned();
        // Fast path by checking len <= 4 (these cannot have labels)
        assert!(parse_dns(&short_query).is_err())
    }

    #[test]
    fn filter_unknown_prim() {
        let unknown_prim = b"label.domain.com".to_vec().to_owned();
        let unknown_tld = b"label.domain.localtld".to_vec().to_owned();

        // Make sure our query is valid with a known suffix...
        assert!(parse_dns(&unknown_prim).is_ok());

        // .. and rejected with an unknown suffix
        assert!(parse_dns(&unknown_tld).is_err());
    }

    #[test]
    fn actual_bytes_in_primary_domain() {
        let bytes_in_domain = b"null\x00.linefeed\x0A.carriagereturn\x0D.com".to_vec().to_owned();
        let expected = DnsPayload {
            labels: vec![b"null\x00".to_vec(), b"linefeed\x0A".to_vec()],
            payload_len: 14,
        };

        let (_, result) = parse_dns(&bytes_in_domain).unwrap();
        assert_eq!(expected, result);
    }

    #[test]
    fn payload_lengths() {
        let one_label = b"one.domain.com".to_vec().to_owned();
        let two_label = b"two.two.domain.com".to_vec().to_owned();
        let ten_label = b"a.a.a.a.a.a.a.a.a.a.domain.com".to_vec().to_owned();

        let (_, pl_one) = parse_dns(&one_label).unwrap();
        let (_, pl_two) = parse_dns(&two_label).unwrap();
        let (_, pl_ten) = parse_dns(&ten_label).unwrap();

        assert_eq!(3, pl_one.payload_len);
        assert_eq!(6, pl_two.payload_len);
        assert_eq!(10, pl_ten.payload_len);
    }
}
