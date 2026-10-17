//! Secret scanning with gitleaks.
//!
//! gitleaks walks the git history (every commit, not just the current files)
//! looking for credentials: cloud keys, API tokens, private keys, passwords in
//! URLs, and so on. A secret that was committed and later deleted is still in
//! the history, and still usable by anyone who clones the repository.

use std::io::Write;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use super::{ScanRequest, SecretsScope, last_lines};
use crate::model::{Finding, FindingKind, Severity};
use crate::settings;

/// A gitleaks config that just uses gitleaks' built-in rules.
const DEFAULT_CONFIG: &str = "[extend]\nuseDefault = true\n";

/// Runs gitleaks on the repository's history and converts its report.
pub fn scan(binary: &Path, request: &ScanRequest) -> Result<Vec<Finding>> {
    // SECURITY: like osv-scanner, gitleaks reads settings from the repository
    // it scans, and a malicious repository can use them to hide its secrets:
    //   - `.gitleaks.toml` can replace the rules or allowlist anything,
    //   - `.gitleaksignore` can list findings to ignore,
    //   - `gitleaks:allow` comments in the code suppress findings inline.
    // So we always pass our own config (the user's, or the built-in rules),
    // point the ignore-file lookup at a folder the repository doesn't control,
    // and tell gitleaks to disregard `gitleaks:allow` comments.
    let mut default_config = tempfile::Builder::new()
        .prefix("git-vulnscan-")
        .suffix(".toml")
        .tempfile()
        .context("couldn't create a temporary file")?;
    default_config.write_all(DEFAULT_CONFIG.as_bytes())?;
    let config = settings::user_file("gitleaks.toml")
        .unwrap_or_else(|| default_config.path().to_path_buf());

    // An empty folder: "no ignore file", unless the user has their own.
    let empty_dir = tempfile::tempdir().context("couldn't create a temporary folder")?;
    let ignore = settings::user_file(".gitleaksignore")
        .unwrap_or_else(|| empty_dir.path().to_path_buf());

    let mut command = Command::new(binary);
    command.arg("git").arg(&request.repo);
    command.args([
        "--no-banner",
        "--no-color",
        // Never print the secrets themselves: our output may end up in CI
        // logs or terminal scrollback.
        "--redact",
        // gitleaks exits with 1 when it finds something by default. We want
        // to tell "found secrets" apart from "crashed", so we ask for 0 and
        // read the findings from the report instead.
        "--exit-code",
        "0",
        "--report-format",
        "json",
        // "-" means "write the report to standard output".
        "--report-path",
        "-",
        "--log-level",
        "error",
        "--ignore-gitleaks-allow",
    ]);
    command.arg("--config").arg(&config);
    command.arg("--gitleaks-ignore-path").arg(&ignore);

    // `if let` with a pattern that destructures an enum variant: this block
    // only runs when `secrets` is a `Range`, and binds `from` and `to`.
    if let SecretsScope::Range { from, to } = &request.secrets {
        // Passed through to `git log`: only scan the commits in from..to.
        command.arg("--log-opts").arg(format!("{from}..{to}"));
    }

    let output = command
        .output()
        .with_context(|| format!("failed to run {}", binary.display()))?;
    if !output.status.success() {
        bail!(
            "gitleaks exited with {}: {}",
            output.status,
            last_lines(&output.stderr, 5)
        );
    }
    parse(&output.stdout)
}

/// One leaked secret in gitleaks' JSON report.
///
/// gitleaks uses PascalCase field names ("StartLine"), so we tell serde to
/// map our snake_case fields to that style. `RuleID` doesn't follow the
/// pattern (PascalCase of `rule_id` would be "RuleId"), so it gets an
/// explicit rename.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Leak {
    #[serde(rename = "RuleID")]
    rule_id: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    start_line: u32,
    file: String,
    #[serde(default)]
    commit: String,
    #[serde(default)]
    fingerprint: String,
}

/// Parses gitleaks' JSON report (an array of leaks) into findings.
fn parse(json: &[u8]) -> Result<Vec<Finding>> {
    // Treat "no output at all" the same as an empty list.
    if json.iter().all(u8::is_ascii_whitespace) {
        return Ok(Vec::new());
    }
    let leaks: Vec<Leak> =
        serde_json::from_slice(json).context("couldn't parse gitleaks' JSON output")?;

    // `into_iter()` consumes the Vec, so we can move each leak's Strings into
    // the finding instead of cloning them.
    let findings = leaks
        .into_iter()
        .map(|leak| Finding {
            kind: FindingKind::Secret,
            // We can't know how sensitive a credential is, so they're all
            // "high": serious enough to fail the default threshold.
            severity: Severity::High,
            id: leak.rule_id,
            aliases: Vec::new(),
            title: leak.description,
            file: leak.file,
            line: (leak.start_line > 0).then_some(leak.start_line),
            package: None,
            fixed_in: Vec::new(),
            upgrade_to: None,
            commit: (!leak.commit.is_empty()).then_some(leak.commit),
            url: None,
            fingerprint: (!leak.fingerprint.is_empty()).then_some(leak.fingerprint),
        })
        .collect();
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_report() {
        let findings = parse(include_bytes!("../../tests/fixtures/gitleaks.json")).unwrap();
        assert_eq!(findings.len(), 1);
        let leak = &findings[0];
        assert_eq!(leak.id, "github-pat");
        assert_eq!(leak.file, "config.env");
        assert_eq!(leak.line, Some(1));
        assert_eq!(leak.kind, FindingKind::Secret);
        assert!(leak.commit.as_deref().unwrap().starts_with("7452bc1"));
    }

    #[test]
    fn empty_report() {
        assert!(parse(b"[]").unwrap().is_empty());
        assert!(parse(b"\n").unwrap().is_empty());
    }
}
