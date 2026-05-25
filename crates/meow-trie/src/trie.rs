use std::collections::HashMap;

pub struct DomainTrie<T: Clone + 'static> {
    state: TrieState<T>,
    len: usize,
}

enum TrieState<T> {
    Building(BuildNode<T>),
    Sealed(SealedNode<T>),
}

// ---------------------------------------------------------------------------
// Build phase: HashMap children for O(1) insert.
// ---------------------------------------------------------------------------

struct BuildNode<T> {
    children: HashMap<Box<str>, BuildNode<T>>,
    exact_value: Option<T>,
    star_value: Option<T>,
    dot_value: Option<T>,
}

impl<T> Default for BuildNode<T> {
    fn default() -> Self {
        Self {
            children: HashMap::new(),
            exact_value: None,
            star_value: None,
            dot_value: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Sealed phase: sorted Vec children for compact memory + binary search.
// ---------------------------------------------------------------------------

struct SealedNode<T> {
    children: Box<[(Box<str>, SealedNode<T>)]>,
    exact_value: Option<T>,
    star_value: Option<T>,
    dot_value: Option<T>,
}

impl<T> BuildNode<T> {
    fn into_sealed(self) -> SealedNode<T> {
        let mut children: Vec<(Box<str>, SealedNode<T>)> = self
            .children
            .into_iter()
            .map(|(k, v)| (k, v.into_sealed()))
            .collect();
        children.sort_by(|(a, _), (b, _)| a.as_bytes().cmp(b.as_bytes()));
        SealedNode {
            children: children.into_boxed_slice(),
            exact_value: self.exact_value,
            star_value: self.star_value,
            dot_value: self.dot_value,
        }
    }
}

#[derive(Clone, Copy)]
enum MatchKind {
    Exact,
    Star,
    Dot,
}

impl<T: Clone + 'static> DomainTrie<T> {
    pub fn new() -> Self {
        DomainTrie {
            state: TrieState::Building(BuildNode::default()),
            len: 0,
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
            self.insert_into_tree(rest, data.clone(), MatchKind::Star);
            self.insert_into_tree(rest, data, MatchKind::Dot);
            self.len += 2;
            return true;
        }

        if let Some(rest) = domain.strip_prefix("*.") {
            if rest.is_empty() {
                return false;
            }
            self.insert_into_tree(rest, data, MatchKind::Star);
            self.len += 1;
            return true;
        }

        if let Some(rest) = domain.strip_prefix('.') {
            if rest.is_empty() {
                return false;
            }
            self.insert_into_tree(rest, data, MatchKind::Dot);
            self.len += 1;
            return true;
        }

        self.insert_into_tree(&domain, data, MatchKind::Exact);
        self.len += 1;
        true
    }

    fn insert_into_tree(&mut self, base_domain: &str, value: T, kind: MatchKind) {
        let root = match &mut self.state {
            TrieState::Building(root) => root,
            TrieState::Sealed(_) => return,
        };
        let mut node = root;
        for label in base_domain.rsplit('.') {
            node = node.children.entry(label.into()).or_default();
        }
        match kind {
            MatchKind::Exact => {
                node.exact_value.get_or_insert(value);
            }
            MatchKind::Star => {
                node.star_value.get_or_insert(value);
            }
            MatchKind::Dot => {
                node.dot_value.get_or_insert(value);
            }
        }
    }

    /// Freeze the trie: convert HashMap children to sorted slices.
    /// Frees the HashMap overhead. Idempotent.
    pub fn seal(&mut self) {
        if let TrieState::Building(_) = &self.state {
            let old = std::mem::replace(&mut self.state, TrieState::Building(BuildNode::default()));
            if let TrieState::Building(root) = old {
                self.state = TrieState::Sealed(root.into_sealed());
            }
        }
    }

    pub fn search(&self, domain: &str) -> Option<&T> {
        if self.len == 0 {
            return None;
        }

        let trimmed = domain.trim();
        if trimmed.bytes().any(|b| b.is_ascii_uppercase()) {
            let lower = trimmed.to_ascii_lowercase();
            self.search_inner(lower.trim_end_matches('.'))
        } else {
            self.search_inner(trimmed.trim_end_matches('.'))
        }
    }

    /// Search with a pre-lowercased domain. Skips the case-folding allocation.
    pub fn search_normalized(&self, domain_lower: &str) -> Option<&T> {
        if self.len == 0 {
            return None;
        }
        self.search_inner(domain_lower.trim_end_matches('.'))
    }

    fn search_inner(&self, query: &str) -> Option<&T> {
        if query.is_empty() {
            return None;
        }
        match &self.state {
            TrieState::Building(root) => Self::search_build(root, query),
            TrieState::Sealed(root) => Self::search_sealed(root, query),
        }
    }

    fn search_build<'a>(root: &'a BuildNode<T>, query: &str) -> Option<&'a T> {
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

    fn search_sealed<'a>(root: &'a SealedNode<T>, query: &str) -> Option<&'a T> {
        let labels: smallvec::SmallVec<[&str; 8]> = query.rsplit('.').collect();
        let n = labels.len();
        let mut node = root;
        let mut best: Option<&T> = None;

        for (d, label) in labels.iter().enumerate() {
            let found = node
                .children
                .binary_search_by(|(k, _)| k.as_bytes().cmp(label.as_bytes()));
            match found {
                Err(_) => break,
                Ok(idx) => {
                    node = &node.children[idx].1;
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

    pub fn is_empty(&self) -> bool {
        self.len == 0
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

        #[test]
        fn sealed_matches_unsealed(
            patterns in proptest::collection::vec(
                "[a-z]{1,5}(\\.[a-z]{1,5}){0,3}|\\*\\.[a-z]{1,5}(\\.[a-z]{1,5}){0,2}",
                1..=20,
            ),
            queries in proptest::collection::vec(
                "[a-z]{1,5}(\\.[a-z]{1,5}){0,4}",
                1..=10,
            ),
        ) {
            let mut trie = build_trie(&patterns);
            let unsealed_results: Vec<_> = queries.iter().map(|q| trie.search(q).copied()).collect();
            trie.seal();
            for (q, expected) in queries.iter().zip(unsealed_results.iter()) {
                let sealed_result = trie.search(q).copied();
                prop_assert_eq!(
                    sealed_result,
                    *expected,
                    "sealed/unsealed divergence on query {:?}",
                    q,
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
        assert_eq!(trie.search("www.google.com"), Some(&2));
        assert_eq!(trie.search("foo.other.com"), Some(&1));
    }

    #[test]
    fn test_trie_map_star_beats_dot_same_level() {
        let mut trie = DomainTrie::new();
        trie.insert("*.example.com", 1);
        trie.insert(".example.com", 2);
        assert_eq!(trie.search("foo.example.com"), Some(&1));
        assert_eq!(trie.search("a.b.example.com"), Some(&2));
    }

    #[test]
    fn test_empty_trie() {
        let trie: DomainTrie<i32> = DomainTrie::new();
        assert!(trie.is_empty());
        assert_eq!(trie.search("anything.com"), None);
    }

    #[test]
    fn test_sealed_search() {
        let mut trie = DomainTrie::new();
        trie.insert("example.com", 1);
        trie.insert("*.example.com", 2);
        trie.insert(".example.com", 3);
        trie.seal();
        assert_eq!(trie.search("example.com"), Some(&1));
        assert_eq!(trie.search("foo.example.com"), Some(&2));
        assert_eq!(trie.search("a.b.example.com"), Some(&3));
        assert_eq!(trie.search("other.com"), None);
    }
}
