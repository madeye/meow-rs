use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

pub struct DomainTrie<T: Clone + 'static> {
    entries: Mutex<Vec<Entry<T>>>,
    len: usize,
    compiled: OnceLock<Compiled<T>>,
}

struct Entry<T> {
    base_domain: String,
    value: T,
    kind: MatchKind,
}

#[derive(Clone, Copy)]
enum MatchKind {
    Exact,
    Star,
    Dot,
}

// ---------------------------------------------------------------------------
// Prefix trie node for the ZST path (0% false-positive rate).
// Labels are stored in reverse order (TLD first): com → google → www.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct TrieNode {
    children: HashMap<Box<str>, TrieNode>,
    exact: bool,
    star: bool,
    dot: bool,
}

// ---------------------------------------------------------------------------
// Prefix trie node for the value-bearing path.
// Same reverse-label structure, but stores actual values at each match slot.
// ---------------------------------------------------------------------------

struct TrieMapNode<T> {
    children: HashMap<Box<str>, TrieMapNode<T>>,
    exact_value: Option<T>,
    star_value: Option<T>,
    dot_value: Option<T>,
}

impl<T> Default for TrieMapNode<T> {
    fn default() -> Self {
        Self {
            children: HashMap::new(),
            exact_value: None,
            star_value: None,
            dot_value: None,
        }
    }
}

enum Compiled<T> {
    Empty,
    /// ZST path: real prefix trie — 0% false-positive rate.
    TrieCheck {
        root: TrieNode,
        value: T,
    },
    /// Value-bearing path: prefix trie with values stored at nodes.
    /// Priority: exact > star (most-specific) > dot (most-specific).
    TrieMap {
        root: TrieMapNode<T>,
    },
}

impl<T: Clone + 'static> DomainTrie<T> {
    pub fn new() -> Self {
        DomainTrie {
            entries: Mutex::new(Vec::new()),
            len: 0,
            compiled: OnceLock::new(),
        }
    }

    pub fn insert(&mut self, domain: &str, data: T) -> bool {
        let domain = domain.trim().to_lowercase();
        if domain.is_empty() {
            return false;
        }

        if let Some(rest) = domain.strip_prefix("+.") {
            if rest.is_empty() {
                return false;
            }
            let entries = self.entries.get_mut().unwrap();
            entries.push(Entry {
                base_domain: rest.to_string(),
                value: data.clone(),
                kind: MatchKind::Star,
            });
            entries.push(Entry {
                base_domain: rest.to_string(),
                value: data,
                kind: MatchKind::Dot,
            });
            self.len += 2;
            return true;
        }

        if let Some(rest) = domain.strip_prefix("*.") {
            if rest.is_empty() {
                return false;
            }
            let entries = self.entries.get_mut().unwrap();
            entries.push(Entry {
                base_domain: rest.to_string(),
                value: data,
                kind: MatchKind::Star,
            });
            self.len += 1;
            return true;
        }

        if let Some(rest) = domain.strip_prefix('.') {
            if rest.is_empty() {
                return false;
            }
            let entries = self.entries.get_mut().unwrap();
            entries.push(Entry {
                base_domain: rest.to_string(),
                value: data,
                kind: MatchKind::Dot,
            });
            self.len += 1;
            return true;
        }

        let entries = self.entries.get_mut().unwrap();
        entries.push(Entry {
            base_domain: domain,
            value: data,
            kind: MatchKind::Exact,
        });
        self.len += 1;
        true
    }

    pub fn search(&self, domain: &str) -> Option<&T> {
        if self.len == 0 {
            return None;
        }

        let compiled = self.compiled.get_or_init(|| self.compile());

        let trimmed = domain.trim();
        if trimmed.bytes().any(|b| b.is_ascii_uppercase()) {
            let lower = trimmed.to_ascii_lowercase();
            Self::search_compiled(compiled, lower.trim_end_matches('.'))
        } else {
            Self::search_compiled(compiled, trimmed.trim_end_matches('.'))
        }
    }

    fn search_compiled<'a>(compiled: &'a Compiled<T>, query: &str) -> Option<&'a T> {
        if query.is_empty() {
            return None;
        }

        match compiled {
            Compiled::Empty => None,
            Compiled::TrieCheck { root, value } => {
                let labels: smallvec::SmallVec<[&str; 8]> = query.rsplit('.').collect();
                let n = labels.len();
                let mut node = root;

                for (d, label) in labels.iter().enumerate() {
                    match node.children.get(*label) {
                        None => return None,
                        Some(child) => {
                            node = child;
                            let remaining = n - d - 1;
                            if remaining == 0 && node.exact {
                                return Some(value);
                            }
                            if remaining == 1 && node.star {
                                return Some(value);
                            }
                            if remaining > 0 && node.dot {
                                return Some(value);
                            }
                        }
                    }
                }
                None
            }
            Compiled::TrieMap { root } => {
                let labels: smallvec::SmallVec<[&str; 8]> = query.rsplit('.').collect();
                let n = labels.len();
                let mut node = root;
                let mut best: Option<&T> = None;

                for (d, label) in labels.iter().enumerate() {
                    match node.children.get(*label) {
                        None => break,
                        Some(child) => {
                            node = child;
                            let remaining = n - d - 1;
                            if remaining == 0 {
                                if let Some(ref v) = node.exact_value {
                                    return Some(v);
                                }
                            } else if remaining == 1 {
                                if let Some(ref v) = node.star_value {
                                    best = Some(v);
                                } else if let Some(ref v) = node.dot_value {
                                    best = Some(v);
                                }
                            } else if let Some(ref v) = node.dot_value {
                                best = Some(v);
                            }
                        }
                    }
                }
                best
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn compile(&self) -> Compiled<T> {
        let entries: Vec<Entry<T>> = {
            let mut guard = self.entries.lock().unwrap();
            std::mem::take(&mut *guard)
        };

        if entries.is_empty() {
            return Compiled::Empty;
        }

        if std::mem::size_of::<T>() == 0 {
            Self::compile_trie_check(&entries)
        } else {
            Self::compile_trie_map(entries)
        }
    }

    fn compile_trie_map(entries: Vec<Entry<T>>) -> Compiled<T> {
        let mut root = TrieMapNode::default();

        for e in entries {
            let mut node = &mut root;
            for label in e.base_domain.rsplit('.') {
                node = node.children.entry(label.into()).or_default();
            }
            match e.kind {
                MatchKind::Exact => {
                    node.exact_value.get_or_insert(e.value);
                }
                MatchKind::Star => {
                    node.star_value.get_or_insert(e.value);
                }
                MatchKind::Dot => {
                    node.dot_value.get_or_insert(e.value);
                }
            }
        }

        Compiled::TrieMap { root }
    }

    fn compile_trie_check(entries: &[Entry<T>]) -> Compiled<T> {
        let mut root = TrieNode::default();

        for e in entries {
            let mut node = &mut root;
            for label in e.base_domain.rsplit('.') {
                node = node.children.entry(label.into()).or_default();
            }
            match e.kind {
                MatchKind::Exact => node.exact = true,
                MatchKind::Star => node.star = true,
                MatchKind::Dot => node.dot = true,
            }
        }

        // Safety: T is a ZST (size_of::<T>() == 0), all bit patterns are valid
        let value = unsafe {
            #[allow(clippy::uninit_assumed_init)]
            std::mem::MaybeUninit::<T>::uninit().assume_init()
        };

        Compiled::TrieCheck { root, value }
    }
}

impl<T: Clone + 'static> Default for DomainTrie<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

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
                    if let Some(prefix) = q.strip_suffix(&format!(".{rest}")) {
                        if !prefix.is_empty() && !prefix.contains('.') {
                            return true;
                        }
                    }
                } else if let Some(rest) = pat.strip_prefix('.') {
                    if q.ends_with(&format!(".{rest}")) {
                        return true;
                    }
                } else if q == pat.as_str() {
                    return true;
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

        #[test]
        fn matches_naive_reference_zst(
            patterns in proptest::collection::vec(
                "[a-z]{1,5}(\\.[a-z]{1,5}){0,3}|\\*\\.[a-z]{1,5}(\\.[a-z]{1,5}){0,2}",
                1..=20,
            ),
            queries in proptest::collection::vec(
                "[a-z]{1,5}(\\.[a-z]{1,5}){0,4}",
                1..=10,
            ),
        ) {
            let mut trie: DomainTrie<()> = DomainTrie::new();
            for p in &patterns {
                trie.insert(p, ());
            }
            let naive = NaiveMatcher::new(&patterns);
            for q in &queries {
                let trie_hit = trie.search(q).is_some();
                let naive_hit = naive.matches(q);
                prop_assert_eq!(
                    trie_hit,
                    naive_hit,
                    "ZST divergence on query {:?} with patterns {:?}",
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
        assert_eq!(trie.search("a.b.example.com"), None);
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
        assert_eq!(trie.search("www.example.com"), Some(&1));
        assert_eq!(trie.search("a.b.example.com"), Some(&1));
    }

    #[test]
    fn test_priority() {
        let mut trie = DomainTrie::new();
        trie.insert("www.example.com", 1);
        trie.insert("*.example.com", 2);
        trie.insert(".example.com", 3);
        assert_eq!(trie.search("www.example.com"), Some(&1));
        assert_eq!(trie.search("foo.example.com"), Some(&2));
        assert_eq!(trie.search("a.b.example.com"), Some(&3));
    }

    #[test]
    fn test_case_insensitive() {
        let mut trie = DomainTrie::new();
        trie.insert("Example.COM", 1);
        assert_eq!(trie.search("example.com"), Some(&1));
        assert_eq!(trie.search("EXAMPLE.COM"), Some(&1));
    }

    #[test]
    fn test_many_exact_domains() {
        let mut trie: DomainTrie<()> = DomainTrie::new();
        for i in 0..200 {
            trie.insert(&format!("domain{i}.com"), ());
        }
        assert!(trie.search("domain0.com").is_some());
        assert!(trie.search("domain199.com").is_some());
        assert!(trie.search("domain200.com").is_none());
    }

    #[test]
    fn test_many_star_wildcards() {
        let mut trie: DomainTrie<()> = DomainTrie::new();
        for i in 0..110 {
            trie.insert(&format!("*.suffix{i}.com"), ());
        }
        assert!(trie.search("www.suffix0.com").is_some());
        assert!(trie.search("foo.suffix50.com").is_some());
        assert!(trie.search("suffix0.com").is_none());
        assert!(trie.search("a.b.suffix0.com").is_none());
    }

    #[test]
    fn test_apex_and_wildcard() {
        let mut trie: DomainTrie<()> = DomainTrie::new();
        for i in 0..60 {
            trie.insert(&format!("exact{i}.com"), ());
        }
        for i in 0..60 {
            trie.insert(&format!("+.wild{i}.com"), ());
        }
        assert!(trie.search("exact0.com").is_some());
        assert!(trie.search("sub.wild0.com").is_some());
        assert!(trie.search("a.b.wild0.com").is_some());
    }

    #[test]
    fn test_trie_map_value_retrieval() {
        let mut trie = DomainTrie::new();
        trie.insert("exact.com", 10);
        trie.insert("*.wild.com", 20);
        trie.insert(".deep.com", 30);
        assert_eq!(trie.search("exact.com"), Some(&10));
        assert_eq!(trie.search("foo.wild.com"), Some(&20));
        assert_eq!(trie.search("a.b.deep.com"), Some(&30));
        assert_eq!(trie.search("other.com"), None);
    }

    #[test]
    fn test_trie_map_first_insert_wins() {
        let mut trie = DomainTrie::new();
        trie.insert("*.example.com", 1);
        trie.insert("*.example.com", 2);
        assert_eq!(trie.search("foo.example.com"), Some(&1));
    }

    #[test]
    fn test_trie_map_deep_dot_overrides_shallow() {
        let mut trie = DomainTrie::new();
        trie.insert(".com", 1);
        trie.insert(".google.com", 2);
        // Most specific dot wins
        assert_eq!(trie.search("www.google.com"), Some(&2));
        assert_eq!(trie.search("foo.other.com"), Some(&1));
    }

    #[test]
    fn test_trie_map_star_beats_dot_same_level() {
        let mut trie = DomainTrie::new();
        trie.insert("*.example.com", 1);
        trie.insert(".example.com", 2);
        // Star has priority over dot at the same level
        assert_eq!(trie.search("foo.example.com"), Some(&1));
        // But dot still matches multi-level
        assert_eq!(trie.search("a.b.example.com"), Some(&2));
    }

    #[test]
    fn test_empty_trie() {
        let trie: DomainTrie<i32> = DomainTrie::new();
        assert!(trie.is_empty());
        assert_eq!(trie.search("anything.com"), None);
    }
}
