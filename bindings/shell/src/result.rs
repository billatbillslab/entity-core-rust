//! Verb return shape — the §3.3 variant set from `GUIDE-SHELL-FRAMING.md`.
//!
//! Each shell verb returns `Result<VerbOutput, ShellError>`. Consumers
//! map variants to their modality (DOM scrollback, terminal stdout,
//! Godot palette panes) via a render adapter; verbs themselves are
//! presentation-neutral per guide §3.7.
//!
//! Streaming primitive — `tokio::sync::mpsc::Receiver`. Picked to be
//! drainable on a consumer's cadence (drain-on-tick for `_process`
//! adapters, await-loop for CLI, spawned drain for DOM) without
//! blocking the verb.

use std::fmt;
use tokio::sync::mpsc;

/// Result of a shell verb. Presentation-neutral; the render adapter
/// maps variants to its modality (scrollback line styles, palette
/// form panes, CLI stdout, etc.).
#[derive(Debug)]
pub enum VerbOutput {
    /// A resolved tree path. `pwd` returns this.
    Path(String),

    /// A list of entries, optionally grouped into sections. Most
    /// verbs return a single section (length-1 `sections` vec) —
    /// e.g., `ls` returns one section with no header, `tails`
    /// returns one section with an "active tails (N)" header.
    /// Verbs like `peer list` return multiple sections ("local" +
    /// "remote") so the renderer can display each block with its
    /// own header.
    Listing { sections: Vec<ListingSection> },

    /// One entity (the result of `cat`).
    Entity(EntityView),

    /// A subtree (the result of `tree`).
    Tree(TreeView),

    /// The result of `exec` — handler-defined. Streaming per guide
    /// §3.3 ("Streaming MUST be supported for at least `lines` and
    /// `dispatch`"). Channel close = dispatch complete.
    Dispatch(mpsc::Receiver<DispatchChunk>),

    /// Generic structured info: label/value rows. Used by `info`,
    /// `help`, status-style verbs.
    Info(Vec<InfoRow>),

    /// A stream of textual lines (the result of `tail`). Channel
    /// close = verb done; the only way the stream ends is by the
    /// embedding cancelling the subscription.
    Lines(mpsc::Receiver<StreamChunk>),

    /// A short status message (no data). `cd`, `rm`, `put`,
    /// `disconnect`, `connect` success.
    ///
    /// **Display contract:** the string is user-facing and intended to
    /// be displayed as-is. Verbs format messages with their own prefix
    /// (`"cd: /alice/"`, `"rm: ok"`) — render adapters should pass the
    /// text through without re-prefixing. If an adapter needs styling
    /// or relocalization, it owns the transform; the crate provides
    /// the canonical English string.
    Message(String),
}

/// One section in a `Listing` variant. A section has an optional
/// header and a list of text rows. Sections render in order.
#[derive(Debug, Clone)]
pub struct ListingSection {
    pub header: Option<String>,
    pub entries: Vec<String>,
}

impl ListingSection {
    pub fn flat(entries: Vec<String>) -> Self {
        Self { header: None, entries }
    }

    pub fn with_header(header: impl Into<String>, entries: Vec<String>) -> Self {
        Self { header: Some(header.into()), entries }
    }
}

/// One row in `VerbOutput::Entity`.
#[derive(Debug, Clone)]
pub struct EntityView {
    pub path: String,
    pub entity_type: String,
    pub byte_len: usize,
    /// Formatted body (multi-line text). The verb has already
    /// rendered the bytes into a human-readable form.
    pub body: String,
}

/// One row in `VerbOutput::Tree`.
#[derive(Debug, Clone)]
pub struct TreeEntry {
    pub path: String,
    pub depth: usize,
}

#[derive(Debug, Clone)]
pub struct TreeView {
    pub root: String,
    pub depth_limit: Option<usize>,
    /// DFS order.
    pub entries: Vec<TreeEntry>,
}

/// One row in `VerbOutput::Info`. `label` is `Some` for structured
/// key/value rows (`info`'s "primary peer: <pid>"); `None` for
/// freeform text rows (`help`'s "verb     description" lines). The
/// renderer decides alignment for labeled rows; freeform rows pass
/// through as-is.
#[derive(Debug, Clone)]
pub struct InfoRow {
    pub label: Option<String>,
    pub value: String,
}

impl InfoRow {
    pub fn labeled(label: impl Into<String>, value: impl Into<String>) -> Self {
        Self { label: Some(label.into()), value: value.into() }
    }

    pub fn text(value: impl Into<String>) -> Self {
        Self { label: None, value: value.into() }
    }
}

/// One chunk in a `Lines` stream. The first chunk for an async verb
/// is typically `Dispatched`; intermediate chunks are `Line`s; the
/// final chunk is `Complete` or `Failed`. After the final chunk the
/// channel closes.
#[derive(Debug, Clone)]
pub enum StreamChunk {
    /// "→ verb args" — sync echo before the real work starts.
    Dispatched(String),
    /// One line of output.
    Line(String),
    /// Successful completion + final summary.
    Complete(String),
    /// Verb failed mid-stream.
    Failed(ShellError),
}

/// One chunk in a `Dispatch` stream. Mirrors `StreamChunk` for now;
/// will gain handler-specific structured fields when `exec`'s wire
/// shape matures.
#[derive(Debug, Clone)]
pub enum DispatchChunk {
    Dispatched(String),
    Progress(String),
    /// Successful — the handler-defined summary.
    Complete(String),
    Failed(ShellError),
}

/// Structured error for verb failures and the catch-all `Error`
/// return. `Result<VerbOutput, ShellError>` is the verb signature;
/// the adapter renders Errs as styled error lines.
#[derive(Debug, Clone)]
pub struct ShellError {
    pub code: ErrorCode,
    pub message: String,
    /// Optional upstream cause (e.g., SDK error message). Renderer
    /// may show as a dimmed second line.
    pub cause: Option<String>,
}

/// Coarse category for verb errors. Adapter may style differently
/// per code (usage in dim yellow, transport in red, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    /// User-facing input mistake (bad args, missing path argument).
    Usage,
    /// Path / entity / alias not found.
    NotFound,
    /// Unknown verb / subcommand / mode.
    Unknown,
    /// SDK dispatch failure (handler error).
    Dispatch,
    /// Transport / connection failure.
    Transport,
    /// Catch-all.
    Other,
}

impl ShellError {
    pub fn usage(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Usage, message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::NotFound, message)
    }

    pub fn unknown(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Unknown, message)
    }

    pub fn dispatch(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Dispatch, message)
    }

    pub fn transport(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Transport, message)
    }

    pub fn other(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Other, message)
    }

    fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self { code, message: message.into(), cause: None }
    }

    pub fn with_cause(mut self, cause: impl Into<String>) -> Self {
        self.cause = Some(cause.into());
        self
    }
}

impl fmt::Display for ShellError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.cause {
            Some(c) => write!(f, "{} ({})", self.message, c),
            None => write!(f, "{}", self.message),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_error_constructors_set_code() {
        assert_eq!(ShellError::usage("x").code, ErrorCode::Usage);
        assert_eq!(ShellError::not_found("x").code, ErrorCode::NotFound);
        assert_eq!(ShellError::unknown("x").code, ErrorCode::Unknown);
        assert_eq!(ShellError::dispatch("x").code, ErrorCode::Dispatch);
        assert_eq!(ShellError::transport("x").code, ErrorCode::Transport);
        assert_eq!(ShellError::other("x").code, ErrorCode::Other);
    }

    #[test]
    fn shell_error_display_formats_with_optional_cause() {
        let err = ShellError::usage("missing path");
        assert_eq!(err.to_string(), "missing path");

        let err = ShellError::dispatch("execute failed").with_cause("timeout");
        assert_eq!(err.to_string(), "execute failed (timeout)");
    }

    #[test]
    fn variants_compile_with_expected_shapes() {
        // Pattern-check: all 9 guide §3.3 variants present and
        // constructible. Smoke test against the variant set — catches
        // accidental rename / removal.
        let _p: VerbOutput = VerbOutput::Path("/p/foo".into());
        let _l: VerbOutput = VerbOutput::Listing {
            sections: vec![ListingSection::with_header(
                "3 matches",
                vec!["/p/a".into()],
            )],
        };
        let _e: VerbOutput = VerbOutput::Entity(EntityView {
            path: "/p/foo".into(),
            entity_type: "test/t".into(),
            byte_len: 4,
            body: "data".into(),
        });
        let _t: VerbOutput = VerbOutput::Tree(TreeView {
            root: "/p/".into(),
            depth_limit: Some(2),
            entries: vec![TreeEntry { path: "/p/a".into(), depth: 1 }],
        });
        let (_tx, rx) = mpsc::channel::<DispatchChunk>(1);
        let _d: VerbOutput = VerbOutput::Dispatch(rx);
        let _i: VerbOutput = VerbOutput::Info(vec![
            InfoRow::labeled("wd", "/p/"),
            InfoRow::text("(plain text row)"),
        ]);
        let (_tx, rx) = mpsc::channel::<StreamChunk>(1);
        let _ls: VerbOutput = VerbOutput::Lines(rx);
        let _m: VerbOutput = VerbOutput::Message("done".into());
    }
}
