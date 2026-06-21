//! Verb implementations.
//!
//! Each verb is a pure function returning `Result<VerbOutput,
//! ShellError>` per `GUIDE-SHELL-FRAMING.md` §3.7. No scrollback
//! writes, no DOM/renderer references — verbs return typed output;
//! consumer adapters render.
//!
//! Phase 3a-cd ships:
//! - `pwd` — pattern-setter for pure verbs (no peer access).
//! - `cd`  — first peer-touching verb, forces `PeerBinding` +
//!   `SelectionSink` traits to materialize.
//!
//! Tier C continuation (ls, cat, tree, exec, info, connect,
//! disconnect) extends `PeerBinding` with tree-listing + dispatch ops
//! as each lifts.

pub mod bootstrap;
pub mod cat;
pub mod cd;
pub mod compute;
pub mod connect;
pub mod count;
pub mod disconnect;
pub mod exec;
pub mod help;
pub mod info;
pub mod inspect;
pub mod ls;
pub mod open;
pub mod peer;
pub mod put;
pub mod pwd;
pub mod query;
pub mod rm;
pub mod tail;
pub mod tree;

pub use bootstrap::bootstrap;
pub use cat::cat;
pub use cd::cd;
pub use compute::compute;
pub use connect::connect;
pub use count::count;
pub use disconnect::disconnect;
pub use exec::exec;
pub use help::help;
pub use info::info;
pub use inspect::inspect;
pub use ls::ls;
pub use open::open;
pub use peer::peer;
pub use put::put;
pub use pwd::pwd;
pub use query::query;
pub use rm::rm;
pub use tail::{tail, tails, untail};
pub use tree::tree;
