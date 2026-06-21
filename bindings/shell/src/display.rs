//! Small display helpers used across verbs.
//!
//! Consumers can use these or substitute their own — verbs that touch
//! these helpers also expose the full underlying values (e.g.,
//! `InfoRow::value` contains both the full peer-id and the short form
//! when verb output is rendered).

/// Shorten a peer ID for display. Long ids collapse to
/// `{prefix-8}...{suffix-6}`; short ids pass through unchanged.
pub fn short_pid(pid: &str) -> String {
    if pid.len() > 16 {
        format!("{}...{}", &pid[..8], &pid[pid.len() - 6..])
    } else {
        pid.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shortens_long_pids() {
        let pid = "0123456789abcdef0123456789abcdef";
        assert_eq!(short_pid(pid), "01234567...abcdef");
    }

    #[test]
    fn passes_through_short_pids() {
        assert_eq!(short_pid("alice"), "alice");
        assert_eq!(short_pid("0123456789abcdef"), "0123456789abcdef");
    }
}
