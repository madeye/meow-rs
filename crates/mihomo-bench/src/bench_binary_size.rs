use std::path::Path;

pub fn measure_binary_size(path: &Path) -> anyhow::Result<u64> {
    let meta = std::fs::metadata(path)
        .map_err(|e| anyhow::anyhow!("cannot stat {}: {}", path.display(), e))?;
    Ok(meta.len())
}
