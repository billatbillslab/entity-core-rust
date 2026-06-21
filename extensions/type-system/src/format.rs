//! Named-format validators for `system/type/constraint/format` (§4.5).
//!
//! v1.1 strengthens the well-known vocabulary to MUST-recognize:
//! `uri`, `date-time`, `date`, `uuid`, `base58`, `re2`. Unknown format
//! names fail closed with `kind: "unknown_constraint"`.

/// Validate a string value against a named format. Returns `Ok(true)` when
/// the value matches; `Ok(false)` when the format is well-known but the
/// value does not match; `Err(name)` when the format is not recognized
/// (caller turns this into a `kind: "unknown_constraint"` violation per
/// §1.2 / §4.5).
pub fn validate_format(value: &str, format: &str) -> Result<bool, String> {
    match format {
        "uri" => Ok(is_uri(value)),
        "date-time" => Ok(is_rfc3339_datetime(value)),
        "date" => Ok(is_rfc3339_date(value)),
        "uuid" => Ok(is_uuid(value)),
        "base58" => Ok(is_base58(value)),
        "re2" => Ok(regex::Regex::new(value).is_ok()),
        other => Err(other.to_string()),
    }
}

/// RFC 3986 — `scheme ":" hier-part [ "?" query ] [ "#" fragment ]`.
/// Conservative: require non-empty alpha-prefixed scheme + ':' + at least
/// one trailing char. Tighter validators belong to RFC-3986-strict crates;
/// this matches the spec's "valid URI" baseline.
fn is_uri(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let bytes = s.as_bytes();
    if !bytes[0].is_ascii_alphabetic() {
        return false;
    }
    let mut i = 1;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b':' {
            return i + 1 < bytes.len();
        }
        if !(c.is_ascii_alphanumeric() || c == b'+' || c == b'-' || c == b'.') {
            return false;
        }
        i += 1;
    }
    false
}

/// RFC 3339 §5.6 full-date: `YYYY-MM-DD`.
fn is_rfc3339_date(s: &str) -> bool {
    if s.len() != 10 {
        return false;
    }
    let b = s.as_bytes();
    if b[4] != b'-' || b[7] != b'-' {
        return false;
    }
    let year = match parse_uint(&b[0..4]) {
        Some(v) => v,
        None => return false,
    };
    let month = match parse_uint(&b[5..7]) {
        Some(v) => v,
        None => return false,
    };
    let day = match parse_uint(&b[8..10]) {
        Some(v) => v,
        None => return false,
    };
    let _ = year;
    valid_date(month as u32, day as u32, year as u32)
}

/// RFC 3339 date-time: `full-date "T" full-time`. full-time = partial-time
/// time-offset. Accept `Z` or `±HH:MM` offsets. Fractional seconds optional.
fn is_rfc3339_datetime(s: &str) -> bool {
    // Minimum: 1970-01-01T00:00:00Z = 20 chars
    if s.len() < 20 {
        return false;
    }
    let b = s.as_bytes();
    if !is_rfc3339_date(&s[..10]) {
        return false;
    }
    if b[10] != b'T' && b[10] != b't' {
        return false;
    }
    // partial-time: HH:MM:SS [".fraction"]
    if s.len() < 19 || b[13] != b':' || b[16] != b':' {
        return false;
    }
    let hour = match parse_uint(&b[11..13]) {
        Some(v) => v,
        None => return false,
    };
    let minute = match parse_uint(&b[14..16]) {
        Some(v) => v,
        None => return false,
    };
    let second = match parse_uint(&b[17..19]) {
        Some(v) => v,
        None => return false,
    };
    if hour > 23 || minute > 59 || second > 60 {
        // 60 allowed for leap second
        return false;
    }
    let mut i = 19;
    // Optional fractional seconds
    if i < b.len() && b[i] == b'.' {
        i += 1;
        let frac_start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i == frac_start {
            return false;
        }
    }
    // Offset: 'Z'/'z' or ±HH:MM
    if i >= b.len() {
        return false;
    }
    if b[i] == b'Z' || b[i] == b'z' {
        return i + 1 == b.len();
    }
    if b[i] != b'+' && b[i] != b'-' {
        return false;
    }
    if i + 6 != b.len() || b[i + 3] != b':' {
        return false;
    }
    let oh = match parse_uint(&b[i + 1..i + 3]) {
        Some(v) => v,
        None => return false,
    };
    let om = match parse_uint(&b[i + 4..i + 6]) {
        Some(v) => v,
        None => return false,
    };
    oh <= 23 && om <= 59
}

/// RFC 4122: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` (hex, 8-4-4-4-12).
fn is_uuid(s: &str) -> bool {
    if s.len() != 36 {
        return false;
    }
    let b = s.as_bytes();
    for (i, ch) in b.iter().enumerate() {
        match i {
            8 | 13 | 18 | 23 => {
                if *ch != b'-' {
                    return false;
                }
            }
            _ => {
                if !ch.is_ascii_hexdigit() {
                    return false;
                }
            }
        }
    }
    true
}

/// Base58 (Bitcoin alphabet) — used by ENTITY-CORE-PROTOCOL-V7 §7 for peer
/// IDs. Validate by decoding through `bs58`.
fn is_base58(s: &str) -> bool {
    !s.is_empty() && bs58::decode(s).into_vec().is_ok()
}

fn parse_uint(b: &[u8]) -> Option<u64> {
    if b.is_empty() {
        return None;
    }
    let mut v: u64 = 0;
    for &ch in b {
        if !ch.is_ascii_digit() {
            return None;
        }
        v = v
            .checked_mul(10)?
            .checked_add((ch - b'0') as u64)?;
    }
    Some(v)
}

fn valid_date(month: u32, day: u32, year: u32) -> bool {
    if !(1..=12).contains(&month) || day == 0 {
        return false;
    }
    let dim = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
            if leap {
                29
            } else {
                28
            }
        }
        _ => return false,
    };
    day <= dim
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uri_basic() {
        assert!(validate_format("https://example.com/path", "uri").unwrap());
        assert!(validate_format("entity://abc", "uri").unwrap());
        assert!(!validate_format("not a uri", "uri").unwrap());
        assert!(!validate_format("", "uri").unwrap());
    }

    #[test]
    fn date() {
        assert!(validate_format("2026-05-28", "date").unwrap());
        assert!(validate_format("2024-02-29", "date").unwrap()); // leap
        assert!(!validate_format("2023-02-29", "date").unwrap()); // not leap
        assert!(!validate_format("2026-13-01", "date").unwrap());
        assert!(!validate_format("not-a-date", "date").unwrap());
    }

    #[test]
    fn date_time() {
        assert!(validate_format("2026-05-28T10:00:00Z", "date-time").unwrap());
        assert!(validate_format("2026-05-28T10:00:00.123Z", "date-time").unwrap());
        assert!(validate_format("2026-05-28T10:00:00+00:00", "date-time").unwrap());
        assert!(validate_format("2026-05-28T10:00:00-05:30", "date-time").unwrap());
        assert!(!validate_format("2026-05-28", "date-time").unwrap());
        assert!(!validate_format("2026-05-28T10:00:00", "date-time").unwrap()); // no offset
    }

    #[test]
    fn uuid() {
        assert!(validate_format(
            "550e8400-e29b-41d4-a716-446655440000",
            "uuid"
        )
        .unwrap());
        assert!(!validate_format("not-a-uuid", "uuid").unwrap());
        assert!(!validate_format(
            "550e8400-e29b-41d4-a716-44665544000G",
            "uuid"
        )
        .unwrap());
    }

    #[test]
    fn base58_format() {
        assert!(validate_format("3Mb2", "base58").unwrap());
        assert!(!validate_format("0OIl", "base58").unwrap()); // invalid b58 chars
    }

    #[test]
    fn re2_format() {
        assert!(validate_format("^[a-z]+$", "re2").unwrap());
        assert!(!validate_format("(", "re2").unwrap()); // invalid regex
    }

    #[test]
    fn unknown_format_errors() {
        let err = validate_format("anything", "email").unwrap_err();
        assert_eq!(err, "email");
    }
}
