//! Domain trie for efficient pattern matching in the meow-rs proxy kernel.
//!
//! [`DomainTrie`] stores exact names and suffixes so rule matching can look
//! up a hostname without scanning the full rule list.

mod trie;
pub use trie::DomainTrie;
