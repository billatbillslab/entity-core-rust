//! Glob pattern matching for `type_pattern` constraints (§4.6).
//!
//! Semantics:
//! - `*` matches zero or more characters within a single path segment
//!   (does not cross `/`).
//! - `**` matches zero or more characters across any number of segments
//!   (may cross `/`).
//! - The compound `**/` matches zero or more whole segments — i.e.,
//!   `a/**/b` matches both `a/b` and `a/x/y/b`. This is the conventional
//!   globstar interpretation; the spec's §4.6 example is consistent with it.
//! - All other characters match literally.

/// Match a path-like type string against a glob pattern.
pub fn glob_match(pattern: &str, value: &str) -> bool {
    glob_match_impl(pattern.as_bytes(), value.as_bytes())
}

fn glob_match_impl(pat: &[u8], val: &[u8]) -> bool {
    // `**/` — zero-or-more whole segments (each followed by `/`).
    if pat.starts_with(b"**/") {
        let rest = &pat[3..];
        // Case 1: ** matches zero segments — drop the **/ entirely.
        if glob_match_impl(rest, val) {
            return true;
        }
        // Case 2: ** matches one or more segments — consume up through a '/'.
        for i in 0..val.len() {
            if val[i] == b'/' && glob_match_impl(rest, &val[i + 1..]) {
                return true;
            }
        }
        return false;
    }
    // Bare `**` — zero-or-more arbitrary chars (may cross `/`).
    if pat.starts_with(b"**") {
        let rest = &pat[2..];
        for i in 0..=val.len() {
            if glob_match_impl(rest, &val[i..]) {
                return true;
            }
        }
        return false;
    }
    // Single `*` — zero-or-more chars within one segment (no `/`).
    if pat.first() == Some(&b'*') {
        let rest = &pat[1..];
        for i in 0..=val.len() {
            if i > 0 && val[i - 1] == b'/' {
                break;
            }
            if glob_match_impl(rest, &val[i..]) {
                return true;
            }
        }
        return false;
    }
    // Literal byte match.
    if val.is_empty() {
        return pat.is_empty();
    }
    if pat.is_empty() {
        return false;
    }
    if pat[0] == val[0] {
        return glob_match_impl(&pat[1..], &val[1..]);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_match() {
        assert!(glob_match("foo/bar", "foo/bar"));
        assert!(!glob_match("foo/bar", "foo/baz"));
    }

    #[test]
    fn single_star_segment_scoped() {
        assert!(glob_match("system/capability/*", "system/capability/grant-entry"));
        assert!(!glob_match(
            "system/capability/*",
            "system/capability/path-scope/foo"
        ));
        assert!(glob_match("foo/*/bar", "foo/x/bar"));
        assert!(!glob_match("foo/*/bar", "foo/x/y/bar"));
    }

    #[test]
    fn double_star_spans_segments() {
        assert!(glob_match("system/**", "system/x"));
        assert!(glob_match("system/**", "system/x/y/z"));
        assert!(glob_match("**/foo", "a/b/c/foo"));
        assert!(glob_match("a/**/b", "a/b"));
        assert!(glob_match("a/**/b", "a/x/y/b"));
    }

    #[test]
    fn star_within_segment() {
        assert!(glob_match("foo*", "foobar"));
        assert!(glob_match("*bar", "foobar"));
        assert!(glob_match("f*r", "foobar"));
        assert!(!glob_match("foo*", "foo/bar"));
    }
}
