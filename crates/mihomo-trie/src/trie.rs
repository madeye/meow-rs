use std::collections::HashMap;

const WILDCARD: &str = "*";
const DOT_WILDCARD: &str = ".";

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
            let parts_star = Self::split_domain(&format!("*.{rest}"));
            let parts_dot = Self::split_domain(&format!(".{rest}"));
            if let Some(parts) = parts_star {
                self.insert_parts(&parts, data.clone());
            }
            if let Some(parts) = parts_dot {
                self.insert_parts(&parts, data);
            }
            return true;
        }

        if let Some(parts) = Self::split_domain(&domain) {
            self.insert_parts(&parts, data);
            true
        } else {
            false
        }
    }

    fn insert_parts(&mut self, parts: &[String], data: T) {
        let mut node = &mut self.root;
        for part in parts {
            node = node.children.entry(part.clone()).or_insert_with(Node::new);
        }
        node.data = Some(data);
    }

    pub fn search(&self, domain: &str) -> Option<&T> {
        let domain = domain.trim().to_lowercase();
        let parts = Self::split_domain(&domain)?;
        self.search_node(&self.root, &parts)
    }

    fn search_node<'a>(&'a self, node: &'a Node<T>, parts: &[String]) -> Option<&'a T> {
        if parts.is_empty() {
            return node.data.as_ref();
        }

        let part = &parts[0];
        let rest = &parts[1..];

        // Priority 1: exact match
        if let Some(child) = node.children.get(part.as_str()) {
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

    /// Split domain into reversed parts: "www.example.com" -> ["com", "example", "www"]
    /// Leading dot means dot-wildcard: ".example.com" -> ["com", "example", "."]
    fn split_domain(domain: &str) -> Option<Vec<String>> {
        let domain = domain.trim_end_matches('.');
        if domain.is_empty() {
            return None;
        }

        let (prefix, domain) = if let Some(stripped) = domain.strip_prefix('.') {
            (Some(DOT_WILDCARD), stripped)
        } else {
            (None, domain)
        };

        let mut parts: Vec<String> = domain
            .split('.')
            .rev()
            .map(std::string::ToString::to_string)
            .collect();
        if let Some(p) = prefix {
            parts.push(p.to_string());
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
