//! Root mapping configuration, path translation, and glob filters
//! (DOMAIN-LOCAL-FILES §2.5, §8).

use std::path::{Component, Path, PathBuf};

use crate::types::RootConfigData;

/// In-memory root mapping. The handler holds a name → `RootMapping` map.
#[derive(Debug, Clone)]
pub struct RootMapping {
    pub name: String,
    /// Tree prefix (e.g., `"local/files/shared/"`). Always ends with `/`.
    pub prefix: String,
    /// Filesystem root, canonicalized when possible (e.g., `/home/alice/shared`).
    pub fs_root: PathBuf,
    pub read_only: bool,
    pub exclude: Vec<String>,
    pub include: Vec<String>,
    pub publish_descriptors: bool,
}

impl RootMapping {
    pub fn from_config(name: String, cfg: &RootConfigData) -> Result<Self, String> {
        let mut prefix = cfg.prefix.clone();
        if !prefix.is_empty() && !prefix.ends_with('/') {
            prefix.push('/');
        }
        let fs_root_path = Path::new(&cfg.filesystem_root);
        let fs_root = fs_root_path
            .canonicalize()
            .unwrap_or_else(|_| {
                // Root may not exist yet; absolutize without canonicalizing.
                if fs_root_path.is_absolute() {
                    fs_root_path.to_path_buf()
                } else {
                    std::env::current_dir()
                        .map(|c| c.join(fs_root_path))
                        .unwrap_or_else(|_| fs_root_path.to_path_buf())
                }
            });
        Ok(RootMapping {
            name,
            prefix,
            fs_root,
            read_only: cfg.read_only,
            exclude: cfg.exclude.clone(),
            include: cfg.include.clone(),
            publish_descriptors: cfg.publish_descriptors,
        })
    }
}

/// Resolve a tree path inside a root mapping to (filesystem_path,
/// relative_path).
///
/// Applies both v1.3 §8.3 defenses:
///
/// 1. **Parent-traversal MUST.** Reject `..` segments in the input path
///    (closes the `local/files/shared/../etc/passwd` exploit).
/// 2. **Leaf-symlink MUST (interim).** `lstat` the resolved target; if
///    it's a symlink, reject with `path_traversal_rejected`. This is the
///    spec-pinned interim mitigation per §8.3 — it closes the trivial
///    leaf-symlink exploit at the cost of a narrow TOCTOU window
///    between the lstat and the subsequent open. The kernel-enforced
///    fix (`cap-std` / `openat2(RESOLVE_BENEATH)`) is scheduled as the
///    second-pass migration; until then this is the conformant
///    interim defense per §8.3.
///
/// **Per §8.3 callsite MUST: every callsite that resolves a tree path to
/// a filesystem path uses this function** — read, write, list, delete,
/// reverse-write, reverse-delete, watcher debounce-flush. Go's L5 audit
/// (commit `ba21372`) found their reverse-* paths bypassing the
/// canonical resolver; Rust has the same shape and the fix is to route
/// those callsites here.
pub fn resolve_fs_path(root: &RootMapping, tree_path: &str) -> Result<(PathBuf, String), String> {
    let relative = tree_path
        .strip_prefix(&root.prefix)
        .ok_or_else(|| "tree path does not start with root prefix".to_string())?;
    if !is_safe_relative(relative) {
        return Err(format!("path traversal rejected: {tree_path}"));
    }
    let fs_path = root.fs_root.join(relative);
    reject_if_leaf_symlink(&fs_path)?;
    Ok((fs_path, relative.to_string()))
}

/// Same as `resolve_fs_path` but takes a relative path directly. Used by
/// watcher and reverse-write paths that already have the relative path
/// in hand (from notify event stripping or tree-event prefix-trim).
pub fn resolve_fs_path_relative(
    root: &RootMapping,
    relative: &str,
) -> Result<PathBuf, String> {
    if !is_safe_relative(relative) {
        return Err(format!("path traversal rejected: {relative}"));
    }
    let fs_path = root.fs_root.join(relative);
    reject_if_leaf_symlink(&fs_path)?;
    Ok(fs_path)
}

/// Leaf-symlink rejection per v1.3 §8.3 (interim non-atomic form).
///
/// Reject any target whose final component is a symlink. Existing-file
/// case: lstat says symlink → reject. New-file case: lstat returns
/// NotFound → accept (we're about to create the file, no symlink yet).
/// Any other lstat error surfaces as a path traversal error to be safe.
///
/// TOCTOU: there is a window between this check and the caller's open.
/// An attacker with concurrent write access to the parent dir could
/// race in a symlink. The spec acknowledges this as the price of the
/// interim form (§8.3); `cap-std`'s `openat2(RESOLVE_BENEATH)` is the
/// kernel-enforced fix scheduled as the second-pass migration.
pub fn reject_if_leaf_symlink(fs_path: &Path) -> Result<(), String> {
    match std::fs::symlink_metadata(fs_path) {
        Ok(md) if md.file_type().is_symlink() => Err(format!(
            "path traversal rejected: leaf is a symlink: {}",
            fs_path.display()
        )),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("path resolution failed: {e}")),
    }
}

/// True if `rel` has no `..` segments and stays within the root logically.
/// Defense in depth — `resolve_fs_path` also checks that the canonicalized
/// result stays under the root for the lookup-path case.
fn is_safe_relative(rel: &str) -> bool {
    let p = Path::new(rel);
    for c in p.components() {
        match c {
            Component::ParentDir => return false,
            Component::RootDir | Component::Prefix(_) => return false,
            _ => {}
        }
    }
    true
}

/// True if `name` matches any of the exclude patterns (filename glob match
/// via `glob::Pattern`, identical wire semantics to Go's `filepath.Match`).
pub fn matches_exclude(name: &str, patterns: &[String]) -> bool {
    patterns
        .iter()
        .any(|p| glob::Pattern::new(p).map(|pat| pat.matches(name)).unwrap_or(false))
}

/// True if `name` passes the include filter. Empty include = pass through
/// (no positive filter). Non-empty = must match at least one pattern.
pub fn matches_include(name: &str, patterns: &[String]) -> bool {
    if patterns.is_empty() {
        return true;
    }
    patterns
        .iter()
        .any(|p| glob::Pattern::new(p).map(|pat| pat.matches(name)).unwrap_or(false))
}

/// Combined file-admission check (§2.5 admission rule).
pub fn file_skipped(name: &str, exclude: &[String], include: &[String]) -> bool {
    if matches_exclude(name, exclude) {
        return true;
    }
    !matches_include(name, include)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(prefix: &str, fs_root: &str) -> RootMapping {
        RootMapping {
            name: "test".to_string(),
            prefix: prefix.to_string(),
            fs_root: PathBuf::from(fs_root),
            read_only: false,
            exclude: vec![],
            include: vec![],
            publish_descriptors: false,
        }
    }

    #[test]
    fn resolve_basic() {
        let r = root("local/files/shared/", "/tmp/shared");
        let (fs, rel) = resolve_fs_path(&r, "local/files/shared/readme.md").unwrap();
        assert_eq!(rel, "readme.md");
        assert_eq!(fs, PathBuf::from("/tmp/shared/readme.md"));
    }

    #[test]
    fn resolve_rejects_dot_dot() {
        let r = root("local/files/shared/", "/tmp/shared");
        let err = resolve_fs_path(&r, "local/files/shared/../etc/passwd").unwrap_err();
        assert!(err.contains("path traversal"));
    }

    #[test]
    fn exclude_matches_glob() {
        let pats = vec!["*.tmp".to_string(), ".git".to_string()];
        assert!(matches_exclude("foo.tmp", &pats));
        assert!(matches_exclude(".git", &pats));
        assert!(!matches_exclude("readme.md", &pats));
    }

    #[test]
    fn include_empty_passes_all() {
        let pats: Vec<String> = vec![];
        assert!(matches_include("foo.md", &pats));
        assert!(matches_include("anything", &pats));
    }

    #[test]
    fn include_non_empty_filters() {
        let pats = vec!["*.md".to_string()];
        assert!(matches_include("readme.md", &pats));
        assert!(!matches_include("readme.txt", &pats));
    }
}
