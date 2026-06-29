use crate::padding::CHECK_MARK;
use crate::util::StringMap;
use std::sync::Arc;

/// Default padding scheme
pub const DEFAULT_PADDING_SCHEME: &str = r#"stop=8
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000"#;

/// PaddingFactory generates padding sizes according to the scheme
#[derive(Debug, Clone)]
pub struct PaddingFactory {
    scheme: StringMap,
    raw_scheme: Vec<u8>,
    stop: u32,
    md5: String,
}

/// Global padding factory
static DEFAULT_FACTORY: std::sync::OnceLock<Arc<PaddingFactory>> = std::sync::OnceLock::new();

impl PaddingFactory {
    /// Create a new PaddingFactory from raw scheme bytes
    pub fn new(raw_scheme: &[u8]) -> Result<Self, String> {
        let scheme = StringMap::from_bytes(raw_scheme);

        let stop = scheme
            .get("stop")
            .ok_or_else(|| "missing 'stop' in padding scheme".to_string())?
            .parse::<u32>()
            .map_err(|_| "invalid 'stop' value".to_string())?;

        let md5_hash = md5::compute(raw_scheme);
        let md5 = format!("{:x}", md5_hash);

        Ok(Self {
            scheme,
            raw_scheme: raw_scheme.to_vec(),
            stop,
            md5,
        })
    }

    /// Get the default padding factory
    ///
    /// Note: This is not the `Default` trait implementation to avoid confusion
    /// with creating a new factory. This returns a shared singleton instance.
    #[allow(clippy::should_implement_trait)]
    pub fn default() -> Arc<Self> {
        DEFAULT_FACTORY
            .get_or_init(|| {
                Arc::new(
                    Self::new(DEFAULT_PADDING_SCHEME.as_bytes())
                        .expect("default padding scheme should be valid"),
                )
            })
            .clone()
    }

    /// Update the default padding factory
    pub fn update_default(raw_scheme: &[u8]) -> Result<(), String> {
        let factory = Arc::new(Self::new(raw_scheme)?);
        DEFAULT_FACTORY
            .set(factory)
            .map_err(|_| "failed to update default factory".to_string())
    }

    /// Get the stop value
    pub fn stop(&self) -> u32 {
        self.stop
    }

    /// Get the MD5 hash of the scheme
    pub fn md5(&self) -> &str {
        &self.md5
    }

    /// Get the raw scheme bytes
    pub fn raw_scheme(&self) -> &[u8] {
        &self.raw_scheme
    }

    /// Generate record payload sizes for a given packet number
    /// Returns a vector of sizes, where CHECK_MARK (-1) indicates a check point
    pub fn generate_record_payload_sizes(&self, pkt: u32) -> Vec<i32> {
        let key = pkt.to_string();
        let Some(spec) = self.scheme.get(&key) else {
            return Vec::new();
        };

        let mut sizes = Vec::new();
        let parts: Vec<&str> = spec.split(',').collect();

        for part in parts {
            let part = part.trim();
            if part == "c" {
                sizes.push(CHECK_MARK);
                continue;
            }

            if let Some((min_str, max_str)) = part.split_once('-') {
                let min_val = min_str.trim().parse::<i64>().unwrap_or(0);
                let max_val = max_str.trim().parse::<i64>().unwrap_or(0);

                if min_val <= 0 || max_val <= 0 {
                    continue;
                }

                let (min_val, max_val) = (min_val.min(max_val), min_val.max(max_val));

                if min_val == max_val {
                    sizes.push(min_val as i32);
                } else {
                    let size = rand::random_range(min_val..=max_val);
                    sizes.push(size as i32);
                }
            }
        }

        sizes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_factory() {
        let factory = PaddingFactory::default();
        assert_eq!(factory.stop(), 8);
        assert!(!factory.md5().is_empty());
    }

    #[test]
    fn test_generate_sizes() {
        let factory = PaddingFactory::default();

        // Packet 0 should be 30-30 (fixed)
        let sizes = factory.generate_record_payload_sizes(0);
        assert_eq!(sizes, vec![30]);

        // Packet 1 should be 100-400 (random in range)
        let sizes = factory.generate_record_payload_sizes(1);
        assert_eq!(sizes.len(), 1);
        assert!(sizes[0] >= 100 && sizes[0] <= 400);
    }

    #[test]
    fn test_check_mark() {
        let scheme = r#"stop=3
2=400-500,c,500-1000"#;
        let factory = PaddingFactory::new(scheme.as_bytes()).unwrap();
        let sizes = factory.generate_record_payload_sizes(2);

        assert!(sizes.len() >= 3);
        assert!(sizes[0] >= 400 && sizes[0] <= 500);
        assert_eq!(sizes[1], CHECK_MARK);
        assert!(sizes[2] >= 500 && sizes[2] <= 1000);
    }

    #[test]
    fn test_md5_hash() {
        let factory1 = PaddingFactory::default();
        let factory2 = PaddingFactory::new(DEFAULT_PADDING_SCHEME.as_bytes()).unwrap();

        assert_eq!(factory1.md5(), factory2.md5());
    }
}
