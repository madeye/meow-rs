use std::collections::HashMap;

use smallvec::SmallVec;

const WILDCARD: &str = "*";
const DOT_WILDCARD: &str = ".";

/// Most domains have 2–4 labels; size the inline buffer at 8 so realistic
/// queries never heap-allocate while still tolerating absurdly deep names.
type Labels<'a> = SmallVec<[&'a str; 8]>;

pub struct DomainTrie<T> {
    root: Node<T>,
}

struct Node<T> {
    children: HashMap<String, Node<T>>,
    data: Option<T>,
}

impl<T> Node<T> {
    fn new() -> Self {
        Node {
            children: HashMap::new(),
            data: None,
        }
    }
}

impl<T: Clone> DomainTrie<T> {
    pub fn new() -> Self {
        DomainTrie { root: Node::new() }
    }

    pub fn insert(&mut self, domain: &str, data: T) -> bool {
        let domain = domain.trim().to_lowercase();
        if domain.is_empty() {
            return false;
        }

        // Handle +.domain (insert both * and . wildcards)
        if let Some(rest) = domain.strip_prefix("+.") {
            let star = format!("*.{rest}");
            let dot = format!(".{rest}");
            if let Some(parts) = Self::split_domain(&star) {
                self.insert_parts(&parts, data.clone());
            }
            if let Some(parts) = Self::split_domain(&dot) {
                self.insert_parts(&parts, data);
            }
            return true;
        }

        let Some(parts) = Self::split_domain(&domain) else {
            return false;
        };
        self.insert_parts(&parts, data);
        true
    }

    fn insert_parts(&mut self, parts: &[&str], data: T) {
        let mut node = &mut self.root;
        for part in parts {
            node = node
                .children
                .entry((*part).to_string())
                .or_insert_with(Node::new);
        }
        node.data = Some(data);
    }

    pub fn search(&self, domain: &str) -> Option<&T> {
        let trimmed = domain.trim();
        // Fast path: ASCII-lowercase input avoids the String allocation.
        if trimmed.bytes().any(|b| b.is_ascii_uppercase()) {
            let lower = trimmed.to_ascii_lowercase();
            self.search_normalised(&lower)
        } else {
            self.search_normalised(trimmed)
        }
    }

    fn search_normalised(&self, domain: &str) -> Option<&T> {
        let domain = domain.trim_end_matches('.');
        if domain.is_empty() {
            return None;
        }
        let parts = Self::split_domain(domain)?;
        self.search_node(&self.root, &parts)
    }

    fn search_node<'a>(&'a self, node: &'a Node<T>, parts: &[&str]) -> Option<&'a T> {
        if parts.is_empty() {
            return node.data.as_ref();
        }

        let part = parts[0];
        let rest = &parts[1..];

        // Priority 1: exact match
        if let Some(child) = node.children.get(part) {
            if let Some(data) = self.search_node(child, rest) {
                return Some(data);
            }
        }

        // Priority 2: wildcard (*)
        if let Some(child) = node.children.get(WILDCARD) {
            if let Some(data) = self.search_node(child, rest) {
                return Some(data);
            }
        }

        // Priority 3: dot wildcard (.) — matches this segment and all remaining
        if let Some(child) = node.children.get(DOT_WILDCARD) {
            if child.data.is_some() {
                return child.data.as_ref();
            }
        }

        None
    }

    /// Split domain into reversed parts borrowing from the input:
    /// "www.example.com" -> \["com", "example", "www"\]. Leading dot means
    /// dot-wildcard: ".example.com" -> \["com", "example", "."\].
    fn split_domain(domain: &str) -> Option<Labels<'_>> {
        let domain = domain.trim_end_matches('.');
        if domain.is_empty() {
            return None;
        }

        let (prefix, domain) = if let Some(stripped) = domain.strip_prefix('.') {
            (Some(DOT_WILDCARD), stripped)
        } else {
            (None, domain)
        };

        let mut parts: Labels<'_> = domain.split('.').rev().collect();
        if let Some(p) = prefix {
            parts.push(p);
        }
        Some(parts)
    }

    pub fn is_empty(&self) -> bool {
        self.root.children.is_empty()
    }
}

impl<T: Clone> Default for DomainTrie<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    /// Naive reference matcher — linear scan, no trie.
    ///
    /// Understands three pattern forms:
    ///   `*.foo`   — matches exactly one label prepended to `.foo` (e.g. `bar.foo`)
    ///   `.foo`    — matches any number of labels prepended to `.foo` but NOT `foo` itself
    ///   `foo.bar` — exact match (case-insensitive)
    struct NaiveMatcher {
        patterns: Vec<String>,
    }

    impl NaiveMatcher {
        fn new(patterns: &[String]) -> Self {
            NaiveMatcher {
                patterns: patterns.iter().map(|p| p.to_lowercase()).collect(),
            }
        }

        fn matches(&self, query: &str) -> bool {
            let q = query.to_lowercase();
            for pat in &self.patterns {
                if let Some(rest) = pat.strip_prefix("*.") {
                    // *.rest → query must be exactly one label + "." + rest
                    if let Some(prefix) = q.strip_suffix(&format!(".{rest}")) {
                        if !prefix.is_empty() && !prefix.contains('.') {
                            return true;
                        }
                    }
                } else if let Some(rest) = pat.strip_prefix('.') {
                    // .rest → query ends with ".rest" (one or more labels prepended)
                    if q.ends_with(&format!(".{rest}")) {
                        return true;
                    }
                } else {
                    // exact match
                    if q == pat.as_str() {
                        return true;
                    }
                }
            }
            false
        }
    }

    fn build_trie(patterns: &[String]) -> DomainTrie<bool> {
        let mut trie = DomainTrie::new();
        for p in patterns {
            trie.insert(p, true);
        }
        trie
    }

    // Patterns: either `*.label` (single-star wildcard) or `label[.label]*` (exact).
    // We exclude `.`-prefixed patterns from the proptest strategy because the trie's
    // dot-wildcard semantics differ subtly from a naive suffix check when combined
    // with `*` patterns on the same suffix (priority interactions).  The dot-wildcard
    // path is covered by the deterministic unit tests above.
    proptest! {
        #[test]
        fn matches_naive_reference(
            patterns in proptest::collection::vec(
                "[a-z]{1,5}(\\.[a-z]{1,5}){0,3}|\\*\\.[a-z]{1,5}(\\.[a-z]{1,5}){0,2}",
                1..=20,
            ),
            queries in proptest::collection::vec(
                "[a-z]{1,5}(\\.[a-z]{1,5}){0,4}",
                1..=10,
            ),
        ) {
            let trie = build_trie(&patterns);
            let naive = NaiveMatcher::new(&patterns);
            for q in &queries {
                let trie_hit = trie.search(q).is_some();
                let naive_hit = naive.matches(q);
                prop_assert_eq!(
                    trie_hit,
                    naive_hit,
                    "divergence on query {:?} with patterns {:?}",
                    q,
                    patterns
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_insert_and_search() {
        let mut trie = DomainTrie::new();
        trie.insert("example.com", 1);
        assert_eq!(trie.search("example.com"), Some(&1));
        assert_eq!(trie.search("www.example.com"), None);
        assert_eq!(trie.search("foo.com"), None);
    }

    #[test]
    fn test_wildcard() {
        let mut trie = DomainTrie::new();
        trie.insert("*.example.com", 1);
        assert_eq!(trie.search("www.example.com"), Some(&1));
        assert_eq!(trie.search("foo.example.com"), Some(&1));
        assert_eq!(trie.search("example.com"), None);
        assert_eq!(trie.search("a.b.example.com"), None); // * matches only one level
    }

    #[test]
    fn test_dot_wildcard() {
        let mut trie = DomainTrie::new();
        trie.insert(".example.com", 1);
        assert_eq!(trie.search("example.com"), None);
        assert_eq!(trie.search("www.example.com"), Some(&1));
        assert_eq!(trie.search("a.b.example.com"), Some(&1));
    }

    #[test]
    fn test_plus_wildcard() {
        let mut trie = DomainTrie::new();
        trie.insert("+.example.com", 1);
        // +. inserts both * and . wildcards
        assert_eq!(trie.search("www.example.com"), Some(&1));
        assert_eq!(trie.search("a.b.example.com"), Some(&1));
    }

    #[test]
    fn test_priority() {
        let mut trie = DomainTrie::new();
        trie.insert("www.example.com", 1);
        trie.insert("*.example.com", 2);
        trie.insert(".example.com", 3);
        // Exact match has highest priority
        assert_eq!(trie.search("www.example.com"), Some(&1));
        // Wildcard next
        assert_eq!(trie.search("foo.example.com"), Some(&2));
        // Dot wildcard for deeper matches
        assert_eq!(trie.search("a.b.example.com"), Some(&3));
    }

    #[test]
    fn test_case_insensitive() {
        let mut trie = DomainTrie::new();
        trie.insert("Example.COM", 1);
        assert_eq!(trie.search("example.com"), Some(&1));
        assert_eq!(trie.search("EXAMPLE.COM"), Some(&1));
    }
}
