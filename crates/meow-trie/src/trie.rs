use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::sync::{Mutex, OnceLock};

use regex::RegexSet;

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

impl MatchKind {
    fn priority(self) -> u8 {
        match self {
            Self::Exact => 0,
            Self::Star => 1,
            Self::Dot => 2,
        }
    }

    fn to_regex(self, domain: &str) -> String {
        let escaped = regex::escape(domain);
        match self {
            Self::Exact => format!("^{escaped}$"),
            Self::Star => format!("^[^.]+\\.{escaped}$"),
            Self::Dot => format!("^.+\\.{escaped}$"),
        }
    }
}

enum Compiled<T> {
    Empty,
    /// For large `DomainTrie<()>` sets (geosite): Bloom-filter matching.
    /// FPR ~0.1% — a false positive causes one domain to hit the wrong
    /// proxy group, which is harmless (the connection fails or retries).
    BloomCheck {
        exact: BloomFilter,
        star: BloomFilter,
        dot: BloomFilter,
        value: T,
    },
    /// For value-mapped tries (small counts): per-entry regex patterns.
    Individual {
        set: RegexSet,
        values: Vec<T>,
        priorities: Vec<u8>,
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
            Compiled::BloomCheck {
                exact,
                star,
                dot,
                value,
            } => {
                if exact.maybe_contains(query) {
                    return Some(value);
                }
                for (i, _) in query.match_indices('.') {
                    let suffix = &query[i..];
                    let prefix = &query[..i];
                    if star.maybe_contains(suffix) && !prefix.contains('.') {
                        return Some(value);
                    }
                    if dot.maybe_contains(suffix) {
                        return Some(value);
                    }
                }
                None
            }
            Compiled::Individual {
                set,
                values,
                priorities,
            } => {
                let matches = set.matches(query);
                let mut best: Option<(u8, usize)> = None;
                for idx in &matches {
                    let pri = priorities[idx];
                    match best {
                        None => best = Some((pri, idx)),
                        Some((best_pri, _)) if pri < best_pri => best = Some((pri, idx)),
                        _ => {}
                    }
                }
                best.map(|(_, idx)| &values[idx])
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

        if std::mem::size_of::<T>() == 0 && entries.len() > 100 {
            Self::compile_bloom(entries)
        } else {
            Self::compile_individual(entries)
        }
    }

    fn compile_individual(entries: Vec<Entry<T>>) -> Compiled<T> {
        let mut patterns = Vec::with_capacity(entries.len());
        let mut values = Vec::with_capacity(entries.len());
        let mut priorities = Vec::with_capacity(entries.len());

        for e in entries {
            patterns.push(e.kind.to_regex(&e.base_domain));
            values.push(e.value);
            priorities.push(e.kind.priority());
        }

        let set = RegexSet::new(&patterns).expect("compile DomainTrie regex set");
        Compiled::Individual {
            set,
            values,
            priorities,
        }
    }

    fn compile_bloom(entries: Vec<Entry<T>>) -> Compiled<T> {
        let mut exact_items: Vec<String> = Vec::new();
        let mut star_items: Vec<String> = Vec::new();
        let mut dot_items: Vec<String> = Vec::new();

        for e in &entries {
            match e.kind {
                MatchKind::Exact => exact_items.push(e.base_domain.clone()),
                MatchKind::Star => star_items.push(format!(".{}", e.base_domain)),
                MatchKind::Dot => dot_items.push(format!(".{}", e.base_domain)),
            }
        }

        // Safety: T is a ZST (size_of::<T>() == 0), all bit patterns are valid
        let value = unsafe {
            #[allow(clippy::uninit_assumed_init)]
            std::mem::MaybeUninit::<T>::uninit().assume_init()
        };

        Compiled::BloomCheck {
            exact: BloomFilter::from_items(&exact_items),
            star: BloomFilter::from_items(&star_items),
            dot: BloomFilter::from_items(&dot_items),
            value,
        }
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
        let num_words = ((num_bits + 63) / 64) as usize;
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
