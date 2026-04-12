use std::process::Command;

/// Measure RSS of a process in bytes via `ps`.
pub fn measure_rss(pid: u32) -> anyhow::Result<u64> {
    let output = Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()?;

    if !output.status.success() {
        anyhow::bail!("ps failed for pid {}", pid);
    }

    let rss_kb: u64 = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .map_err(|e| anyhow::anyhow!("parse RSS: {}", e))?;

    Ok(rss_kb * 1024)
}

/// Sample RSS repeatedly over a duration, return peak.
pub async fn measure_peak_rss(pid: u32, duration_secs: u64) -> anyhow::Result<u64> {
    let mut peak = 0u64;
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(duration_secs);

    while tokio::time::Instant::now() < deadline {
        if let Ok(rss) = measure_rss(pid) {
            peak = peak.max(rss);
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    }

    Ok(peak)
}
