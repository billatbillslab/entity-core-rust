//! Pure path helpers — peer-id extraction, working-directory
//! resolution, segment normalization. No dependencies; operate on
//! `&str`.
//!
//! Lifted verbatim from egui's `src/views/shell/model.rs` per the
//! Phase 1 notes' clean-zone table.

/// Extract the owning peer id from a tree path. Path shape is
/// `/{peer_id}/...`; returns `None` for non-conforming inputs.
pub fn peer_id_of(path: &str) -> Option<String> {
    let rest = path.strip_prefix('/')?;
    let pid = rest.split('/').next()?;
    if pid.is_empty() { None } else { Some(pid.to_string()) }
}

/// Resolve a verb-supplied path against the current working
/// directory. Rules:
/// - Absolute (`/...`): replace, after `.`/`..` normalization.
/// - `..` walks up one level, but never above `/{peer_id}`.
/// - Relative: join with wd. The result keeps wd's trailing-slash
///   convention when `input` is a directory-style navigation (`.`,
///   `..`, or ends with `/`); leaf inputs (`bar`, `../baz`) produce
///   a leaf-form result regardless.
pub fn resolve(wd: &str, input: &str) -> String {
    if input.starts_with('/') {
        return normalize(input);
    }
    if input.is_empty() {
        return wd.to_string();
    }
    let wd_was_dir = wd.ends_with('/');
    let combined = format!("{}/{}", wd.trim_end_matches('/'), input);
    let normalized = normalize(&combined);
    let input_indicates_dir = input.ends_with('/')
        || matches!(input, "." | "..")
        || input.ends_with("/.")
        || input.ends_with("/..");
    if wd_was_dir && input_indicates_dir && !normalized.ends_with('/') {
        format!("{}/", normalized)
    } else {
        normalized
    }
}

/// Normalize a path's `.`/`..` segments. `..` walks up one level, but
/// never above index 0 (the peer-id segment).
pub fn normalize(path: &str) -> String {
    let leading_slash = path.starts_with('/');
    let mut out: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            // Refuse to walk above the peer-id segment (index 0).
            if out.len() > 1 {
                out.pop();
            }
            continue;
        }
        out.push(seg);
    }
    let body = out.join("/");
    if body.is_empty() {
        return if leading_slash { "/".into() } else { String::new() };
    }
    if leading_slash {
        format!("/{}", body)
    } else {
        body
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_id_of_extracts_first_segment() {
        assert_eq!(peer_id_of("/alice/"), Some("alice".into()));
        assert_eq!(peer_id_of("/alice/system/identity"), Some("alice".into()));
        assert_eq!(peer_id_of("alice"), None);
        assert_eq!(peer_id_of("/"), None);
        assert_eq!(peer_id_of(""), None);
    }

    #[test]
    fn resolve_absolute_replaces() {
        assert_eq!(resolve("/alice/foo/", "/bob/bar"), "/bob/bar");
    }

    #[test]
    fn resolve_relative_joins() {
        assert_eq!(resolve("/alice/", "system"), "/alice/system");
        assert_eq!(resolve("/alice/system", "../app"), "/alice/app");
    }

    #[test]
    fn resolve_dot_dot_capped_at_peer_root() {
        assert_eq!(resolve("/alice/system/", "../../.."), "/alice/");
    }

    #[test]
    fn resolve_preserves_trailing_slash_for_directory_inputs() {
        assert_eq!(resolve("/alice/", "system/"), "/alice/system/");
        assert_eq!(resolve("/alice/sys/", ".."), "/alice/");
    }

    #[test]
    fn normalize_strips_redundant_segments() {
        assert_eq!(normalize("/alice/./foo/../bar"), "/alice/bar");
    }
}
