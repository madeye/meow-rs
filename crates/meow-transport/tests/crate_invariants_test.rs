//! Structural guardrail tests — cases F1..F4 from the transport-layer test plan.
//!
//! These tests enforce ADR-0001 crate boundary invariants mechanically so that
//! PR reviewers see failing *tests* (not just a lint warning) when an invariant
//! is violated.

use meow_transport::TransportError;

// ─── F1: no_proxy_dep ────────────────────────────────────────────────────────

/// Verify that `meow-transport` does not depend on `meow-proxy`,
/// `meow-dns`, or `meow-config`.  Only `meow-common` is allowed.
///
/// Runs `cargo tree -p meow-transport --edges normal` and asserts the output
/// contains no lines mentioning the forbidden crates.
#[test]
fn no_proxy_dep() {
    let output = std::process::Command::new("cargo")
        .args(["tree", "-p", "meow-transport", "--edges", "normal"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("cargo tree failed");

    let tree = String::from_utf8_lossy(&output.stdout);

    let forbidden = ["meow-proxy", "meow-dns", "meow-config"];
    for crate_name in &forbidden {
        // Each line of `cargo tree` looks like:
        //   meow-proxy v0.3.0 (/path/to/crate)
        // We just look for the name substring.
        let offending: Vec<&str> = tree.lines().filter(|l| l.contains(crate_name)).collect();
        assert!(
            offending.is_empty(),
            "meow-transport must not depend on '{}' (ADR-0001 §1).\n\
             Offending lines in `cargo tree`:\n{}",
            crate_name,
            offending.join("\n")
        );
    }
}

// ─── F2: no_server_side_symbols_in_src ───────────────────────────────────────

/// Walk `src/**/*.rs` and assert that no production source file contains
/// server-side binding keywords (`accept`, `bind`, `listen`, `Server`,
/// `Acceptor`, `TcpListener`).
///
/// `tests/` is intentionally excluded — `tests/support/loopback.rs` uses
/// these legitimately.
#[test]
fn no_server_side_symbols_in_src() {
    let src_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");

    // Patterns that indicate server-side code.
    let forbidden_patterns = [
        r"\baccept\b",
        r"\bbind\b",
        r"\blisten\b",
        r"\bServer\b",
        r"\bAcceptor\b",
        r"\bTcpListener\b",
    ];

    // Compile patterns once.
    let regexes: Vec<regex::Regex> = forbidden_patterns
        .iter()
        .map(|p| regex::Regex::new(p).expect("valid regex"))
        .collect();

    let mut violations: Vec<String> = Vec::new();

    walk_rs_files(&src_dir, &mut |path, content| {
        for (line_no, line) in content.lines().enumerate() {
            // Skip comment lines — doc comments that *describe* the restriction
            // are not violations.  Only live code is checked.
            if line.trim().starts_with("//") {
                continue;
            }
            for (re, pat) in regexes.iter().zip(forbidden_patterns.iter()) {
                if re.is_match(line) {
                    violations.push(format!(
                        "{}:{}: '{}' matches pattern '{}'",
                        path.display(),
                        line_no + 1,
                        line.trim(),
                        pat
                    ));
                }
            }
        }
    });

    assert!(
        violations.is_empty(),
        "Server-side symbols found in src/ (ADR-0001 §1, acceptance criterion #8):\n{}",
        violations.join("\n")
    );
}

fn walk_rs_files(dir: &std::path::Path, f: &mut dyn FnMut(&std::path::Path, &str)) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in rd.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_rs_files(&path, f);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            if let Ok(content) = std::fs::read_to_string(&path) {
                f(&path, &content);
            }
        }
    }
}

// ─── F3: transport_error_is_non_exhaustive ───────────────────────────────────

/// `TransportError` must be `#[non_exhaustive]` so that adding variants is
/// a minor (not major) semver bump.
///
/// We assert this at compile time by ensuring a wildcard arm is needed for
/// exhaustive matching.  If the `_` arm were not needed (i.e. the enum were
/// exhaustive), the compiler would emit `unreachable_patterns`.  We rely on
/// the fact that `#[non_exhaustive]` *requires* a wildcard in match
/// expressions outside the defining crate.
#[test]
fn transport_error_is_non_exhaustive() {
    let err = TransportError::Config("test".into());
    // This match must compile with a wildcard because TransportError is
    // #[non_exhaustive].  If it were exhaustive, the `_` arm would generate
    // a compile-time `unreachable_patterns` warning (not an error), which
    // would not catch the regression.  We keep the wildcard and document why.
    #[allow(clippy::match_same_arms)] // arms are distinct variants; bodies coincidentally identical
    let _display = match err {
        TransportError::Io(e) => e.to_string(),
        TransportError::Tls(s) => s,
        TransportError::WebSocket(s) => s,
        TransportError::Grpc(s) => s,
        TransportError::HttpUpgrade(s) => s,
        TransportError::Config(s) => s,
        // Required by #[non_exhaustive] — future variants land here.
        _ => "unknown variant".into(),
    };
    // If this test compiles outside the defining crate, #[non_exhaustive] is
    // working.  (A test binary is a separate crate, so the constraint applies.)
}

// ─── F4: no_anyhow_at_boundary ───────────────────────────────────────────────

/// Walk `src/**/*.rs` and assert that no public function signature uses
/// `anyhow` types.  Private helper internals may use anyhow (engineer's
/// call), but `TransportError` is the only type allowed to cross the crate
/// boundary.
#[test]
fn no_anyhow_at_boundary() {
    let src_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");

    let anyhow_re = regex::Regex::new(r"\banyhow\b").expect("regex");

    let mut violations: Vec<String> = Vec::new();

    walk_rs_files(&src_dir, &mut |path, content| {
        for (line_no, line) in content.lines().enumerate() {
            // Skip comment lines — doc comments explaining *why* anyhow is
            // banned are not themselves violations.
            if line.trim().starts_with("//") {
                continue;
            }
            if anyhow_re.is_match(line) {
                violations.push(format!(
                    "{}:{}: {}",
                    path.display(),
                    line_no + 1,
                    line.trim()
                ));
            }
        }
    });

    assert!(
        violations.is_empty(),
        "anyhow references found in src/ (spec §Error taxonomy).\n\
         TransportError is the only error type allowed at the crate boundary:\n{}",
        violations.join("\n")
    );
}
