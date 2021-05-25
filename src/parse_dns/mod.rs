use psl::{List, Psl};
use regex::Regex;
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
    ReservedSuffix,
    NoLabels,
    InvalidPrim,
    NoStorageChannel,
}

const LABEL_SEP: u8 = b'.';

const WWW_LABEL: &[u8] = b"www";
const TUNLAN_TLD: &[u8] = b"tun.lan";
const FILTER_TLD: [&[u8]; 15] = [
    b"arpa",
    b"local",
    b"intranet",
    b"lan",
    b"localhost",
    b"example.com",
    b"example.net",
    b"example.org",
    b"internal",
    b"private",
    b"corp",
    b"home",
    b"invalid",
    b"test",
    b"example",
];

lazy_static! {
    static ref VALID_PRIM_RE: Regex = Regex::new(r"^(_?[a-zA-Z0-9]+[a-zA-Z0-9.-]*[a-zA-Z0-9]?)$").unwrap();
}

/// Parse and validate/filter given byte vector as DNS query.
pub fn parse_dns(dns_query: &[u8]) -> Result<(String, DnsPayload), ParseDnsError> {
    // TODO: thorough test suite

    let q_len = dns_query.len();
    if q_len < 5 { return Err(ParseDnsError::QueryLength); }
    if q_len > 255 { return Err(ParseDnsError::InvalidDnsName); }

    // Parse domain name
    if let Some(domain) = List.domain(&dns_query) {

        // Remove optional trailing dot
        let domain = domain.trim();
        let is_tunlan_prim = domain.as_bytes().eq(TUNLAN_TLD);

        // FILTER: unknown suffix
        if !domain.suffix().is_known() && !is_tunlan_prim {
            return Err(ParseDnsError::UnknownSuffix);
        }

        // FILTER: special use TLD
        for tld in FILTER_TLD {
            if domain.suffix().as_bytes().ends_with(tld) {
                // Skip tun.lan domain used for data collection
                if is_tunlan_prim { continue; }

                return Err(ParseDnsError::ReservedSuffix);
            }
        }

        // Store owned version of primary domain (to return in the end as well)
        let prim = match std::str::from_utf8(domain.as_bytes()) {
            Ok(str) => {
                // Check if domain follows spec
                if !VALID_PRIM_RE.is_match(str) {
                    return Err(ParseDnsError::InvalidPrim);
                }
                String::from(str)
            }
            Err(_) => return Err(ParseDnsError::InvalidPrim)
        };

        // FILTER no labels (check 1)
        if q_len - prim.len() == 0 { return Err(ParseDnsError::NoLabels); }

        // FILTER: no labels (check 2)
        let labels_concat: &[u8] = dns_query.get(..q_len - prim.len() - 1).unwrap_or_default();
        if labels_concat.is_empty() { return Err(ParseDnsError::NoLabels); }

        // FILTER: "www" label
        if labels_concat.len() == 3 && labels_concat.eq(WWW_LABEL) {
            return Err(ParseDnsError::NoStorageChannel);
        }

        // Collect labels in vector
        let labels = labels_concat
            .split(|c| c == &LABEL_SEP)
            .map(|label| label.to_owned())
            .collect::<Vec<Vec<u8>>>();

        // FILTER: empty labels
        let mut payload_len: usize = 0;
        for label in labels.iter() {
            if label.is_empty() || label.len() > 63 { return Err(ParseDnsError::InvalidDnsName); }
            payload_len += label.len();
        }
        payload_len += labels.len() - 1;

        Ok((prim, DnsPayload {
            labels,
            payload_len: payload_len as u8,
        }))
    } else {
        // FILTER: invalid DNS name (could not be parsed)
        Err(ParseDnsError::InvalidDnsName)
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

        let q = b"label1.label2.example.com";
        let (_, result) = parse_dns(&q[..]).unwrap();

        assert_eq!(expected, result)
    }

    #[test]
    fn filter_empty_query() {
        let empty = vec![];
        assert!(parse_dns(&empty).is_err())
    }

    #[test]
    fn filter_no_labels() {
        let no_label = b"example.com".as_ref();
        assert!(parse_dns(&no_label).is_err());
    }

    #[test]
    fn filter_empty_label() {
        let empty_label = b".example.com".as_ref();
        assert!(parse_dns(&empty_label).is_err());
    }

    #[test]
    fn filter_invalid_double_sep() {
        let double_sep_empty = b"..example.com".as_ref();
        assert!(parse_dns(&double_sep_empty).is_err())
    }

    #[test]
    fn filter_invalid_double_sep_not_empty() {
        let double_sep_not_empty = b"test..test.example.com".as_ref();
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
        let root_label = b".".as_ref();
        assert!(parse_dns(&root_label).is_err())
    }

    #[test]
    fn filter_short_query_fast_path() {
        let short_query = b".a.b".as_ref();
        // Fast path by checking len <= 4 (these cannot have labels)
        assert!(parse_dns(&short_query).is_err())
    }

    #[test]
    fn filter_unknown_prim() {
        let unknown_prim = b"label.domain.com".as_ref();
        let unknown_tld = b"label.domain.localtld".as_ref();

        // Make sure our query is valid with a known suffix...
        assert!(parse_dns(&unknown_prim).is_ok());

        // .. and rejected with an unknown suffix
        assert!(parse_dns(&unknown_tld).is_err());
    }

    #[test]
    fn actual_bytes_in_primary_domain() {
        let bytes_in_domain = b"null\x00.linefeed\x0A.carriagereturn\x0D.com".as_ref();
        assert!(parse_dns(&bytes_in_domain).is_err());
    }

    #[test]
    fn payload_lengths() {
        let one_label = b"one.domain.com".as_ref();
        let two_label = b"two.two.domain.com".as_ref();
        let ten_label = b"a.a.a.a.a.a.a.a.a.a.domain.com".as_ref();

        let (_, pl_one) = parse_dns(&one_label).unwrap();
        let (_, pl_two) = parse_dns(&two_label).unwrap();
        let (_, pl_ten) = parse_dns(&ten_label).unwrap();

        assert_eq!(3, pl_one.payload_len);
        assert_eq!(7, pl_two.payload_len);
        assert_eq!(19, pl_ten.payload_len);
    }
}
