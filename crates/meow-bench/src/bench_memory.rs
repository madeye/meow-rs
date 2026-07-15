use std::process::Command;

/// Measure RSS of a process in bytes.
///
/// - Unix: uses `ps -o rss=`
/// - Windows: uses `tasklist` and parses the "Working Set Size" column
pub fn measure_rss(pid: u32) -> anyhow::Result<u64> {
    #[cfg(target_os = "windows")]
    {
        let output = Command::new("tasklist")
            .args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"])
            .output()?;

        if !output.status.success() {
            anyhow::bail!("tasklist failed for pid {pid}");
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        // CSV format: "meow.exe","1234","Console","1","12,345 K","Running"
        // Working Set Size is the 5th field (index 4), in KB with comma separators
        for line in stdout.lines() {
            if line.contains(&pid.to_string()) {
                let fields: Vec<&str> = line.split(',').collect();
                if fields.len() >= 5 {
                    let kb_str = fields[4].trim().trim_matches('"').replace(" K", "").replace(",", "");
                    let rss_kb: u64 = kb_str
                        .parse()
                        .map_err(|e| anyhow::anyhow!("parse RSS: {e}"))?;
                    return Ok(rss_kb * 1024);
                }
            }
        }
        anyhow::bail!("pid {pid} not found in tasklist output");
    }

    #[cfg(not(target_os = "windows"))]
    {
        let output = Command::new("ps")
            .args(["-o", "rss=", "-p", &pid.to_string()])
            .output()?;

        if !output.status.success() {
            anyhow::bail!("ps failed for pid {pid}");
        }

        let rss_kb: u64 = String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse()
            .map_err(|e| anyhow::anyhow!("parse RSS: {e}"))?;

        Ok(rss_kb * 1024)
    }
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
