use std::collections::HashMap;
use std::hash::{Hash, Hasher};
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

enum Compiled<T> {
    Empty,
    /// ZST path: real prefix trie — 0% false-positive rate.
    TrieCheck {
        root: TrieNode,
        value: T,
    },
    /// Value-bearing path: Bloom filters for fast rejection, HashMaps for
    /// exact value retrieval on hits (effective FPR = 0%).
    BloomMap(Box<BloomMapData<T>>),
}

struct BloomMapData<T> {
    exact_bloom: BloomFilter,
    star_bloom: BloomFilter,
    dot_bloom: BloomFilter,
    exact: HashMap<String, T>,
    star: HashMap<String, T>,
    dot: HashMap<String, T>,
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
            Compiled::BloomMap(data) => {
                if data.exact_bloom.maybe_contains(query) {
                    if let Some(v) = data.exact.get(query) {
                        return Some(v);
                    }
                }
                for (i, _) in query.match_indices('.') {
                    let suffix = &query[i..];
                    let prefix = &query[..i];
                    if !prefix.contains('.') && data.star_bloom.maybe_contains(suffix) {
                        if let Some(v) = data.star.get(suffix) {
                            return Some(v);
                        }
                    }
                    if data.dot_bloom.maybe_contains(suffix) {
                        if let Some(v) = data.dot.get(suffix) {
                            return Some(v);
                        }
                    }
                }
                None
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
            Self::compile_trie(&entries)
        } else {
            Self::compile_bloom_map(entries)
        }
    }

    fn compile_bloom_map(entries: Vec<Entry<T>>) -> Compiled<T> {
        let mut exact_items: Vec<String> = Vec::new();
        let mut star_items: Vec<String> = Vec::new();
        let mut dot_items: Vec<String> = Vec::new();
        let mut exact_map: HashMap<String, T> = HashMap::new();
        let mut star_map: HashMap<String, T> = HashMap::new();
        let mut dot_map: HashMap<String, T> = HashMap::new();

        for e in entries {
            match e.kind {
                MatchKind::Exact => {
                    exact_items.push(e.base_domain.clone());
                    exact_map.entry(e.base_domain).or_insert(e.value);
                }
                MatchKind::Star => {
                    let key = format!(".{}", e.base_domain);
                    star_items.push(key.clone());
                    star_map.entry(key).or_insert(e.value);
                }
                MatchKind::Dot => {
                    let key = format!(".{}", e.base_domain);
                    dot_items.push(key.clone());
                    dot_map.entry(key).or_insert(e.value);
                }
            }
        }

        Compiled::BloomMap(Box::new(BloomMapData {
            exact_bloom: BloomFilter::from_items(&exact_items),
            star_bloom: BloomFilter::from_items(&star_items),
            dot_bloom: BloomFilter::from_items(&dot_items),
            exact: exact_map,
            star: star_map,
            dot: dot_map,
        }))
    }

    fn compile_trie(entries: &[Entry<T>]) -> Compiled<T> {
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

// ---------------------------------------------------------------------------
// Bloom filter — ~14.4 bits/item for 0.1% FPR, 10 hash functions.
// Uses double-hashing: h_i(x) = h1(x) + i * h2(x).
// ---------------------------------------------------------------------------

const BLOOM_FPR_BITS_PER_ITEM: f64 = 14.4; // -ln(0.001) / ln(2)^2
const BLOOM_NUM_HASHES: u32 = 10; // -ln(0.001) / ln(2)

struct BloomFilter {
    bits: Vec<u64>,
    num_bits: u64,
    num_hashes: u32,
}

impl BloomFilter {
    fn from_items(items: &[String]) -> Self {
        if items.is_empty() {
            return Self {
                bits: Vec::new(),
                num_bits: 0,
                num_hashes: 0,
            };
        }

        let num_bits = ((items.len() as f64 * BLOOM_FPR_BITS_PER_ITEM).ceil() as u64).max(64);
        let num_words = num_bits.div_ceil(64) as usize;
        let num_bits = num_words as u64 * 64;
        let mut bits = vec![0u64; num_words];

        for item in items {
            let (h1, h2) = Self::double_hash(item);
            for i in 0..BLOOM_NUM_HASHES {
                let idx = (h1.wrapping_add((i as u64).wrapping_mul(h2))) % num_bits;
                bits[(idx / 64) as usize] |= 1u64 << (idx % 64);
            }
        }

        Self {
            bits,
            num_bits,
            num_hashes: BLOOM_NUM_HASHES,
        }
    }

    fn maybe_contains(&self, item: &str) -> bool {
        if self.num_bits == 0 {
            return false;
        }
        let (h1, h2) = Self::double_hash(item);
        for i in 0..self.num_hashes {
            let idx = (h1.wrapping_add((i as u64).wrapping_mul(h2))) % self.num_bits;
            if self.bits[(idx / 64) as usize] & (1u64 << (idx % 64)) == 0 {
                return false;
            }
        }
        true
    }

    fn double_hash(item: &str) -> (u64, u64) {
        let mut hasher1 = std::hash::DefaultHasher::new();
        item.hash(&mut hasher1);
        let h1 = hasher1.finish();

        let mut hasher2 = std::hash::DefaultHasher::new();
        h1.hash(&mut hasher2);
        let h2 = hasher2.finish() | 1; // ensure odd for better distribution

        (h1, h2)
    }

    #[cfg(test)]
    fn size_bytes(&self) -> usize {
        self.bits.len() * 8
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
    fn test_bloom_mode() {
        let mut trie: DomainTrie<()> = DomainTrie::new();
        for i in 0..200 {
            trie.insert(&format!("domain{i}.com"), ());
        }
        assert!(trie.search("domain0.com").is_some());
        assert!(trie.search("domain199.com").is_some());
        assert!(trie.search("domain200.com").is_none());
    }

    #[test]
    fn test_bloom_with_star_wildcards() {
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
    fn test_bloom_apex_and_wildcard() {
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
    fn test_bloom_filter_size() {
        let items: Vec<String> = (0..10000).map(|i| format!("domain{i}.com")).collect();
        let bf = BloomFilter::from_items(&items);
        let size_kb = bf.size_bytes() as f64 / 1024.0;
        // 10k items × 14.4 bits ≈ 18 KB
        assert!(size_kb < 25.0, "bloom filter too large: {size_kb:.1} KB");
        assert!(size_kb > 10.0, "bloom filter too small: {size_kb:.1} KB");

        for item in &items {
            assert!(bf.maybe_contains(item), "false negative for {item}");
        }
    }

    #[test]
    fn test_bloom_false_positive_rate() {
        let items: Vec<String> = (0..10000)
            .map(|i| format!("domain{i}.example.com"))
            .collect();
        let bf = BloomFilter::from_items(&items);

        let mut fp = 0u64;
        let trials = 100_000;
        for i in 0..trials {
            let probe = format!("probe{i}.notindomain.org");
            if bf.maybe_contains(&probe) {
                fp += 1;
            }
        }
        let fpr = fp as f64 / trials as f64;
        assert!(fpr < 0.005, "FPR too high: {fpr:.4} ({fp}/{trials})");
    }

    #[test]
    fn test_empty_trie() {
        let trie: DomainTrie<i32> = DomainTrie::new();
        assert!(trie.is_empty());
        assert_eq!(trie.search("anything.com"), None);
    }
}
