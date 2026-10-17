//! The shared data model: what a *finding* is, how severe it is, and what a
//! finished scan looks like.
//!
//! Every scanner converts its own output format into these types, so the rest
//! of the program (reporting, exit codes, hooks) never needs to know which
//! tool produced a finding.

use serde::Serialize;

use crate::settings::FailOn;

/// How bad a finding is.
///
/// The variants are listed from least to most severe **on purpose**: when you
/// `#[derive(PartialOrd, Ord)]` on an enum, Rust orders the variants by the
/// order they are declared in. That means `Severity::Critical > Severity::Low`
/// is `true`, and we can sort findings or compare them against a threshold
/// with plain comparison operators.
///
/// `Copy` is derived because the enum is tiny (a single byte), so passing it
/// around by value is cheaper and simpler than borrowing it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
// Serde attribute: serialize the variants as "unknown", "low", ... in JSON.
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// The advisory had no score we could use.
    Unknown,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Every severity, from most to least severe. Handy for printing summaries.
    pub const ALL_DESCENDING: [Severity; 5] = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Unknown,
    ];

    /// Converts a CVSS base score (0.0 to 10.0) into the qualitative rating
    /// defined by the CVSS v3 specification.
    pub fn from_cvss_score(score: f64) -> Severity {
        // `match` on ranges of floats isn't allowed, so an if/else chain it is.
        if score >= 9.0 {
            Severity::Critical
        } else if score >= 7.0 {
            Severity::High
        } else if score >= 4.0 {
            Severity::Medium
        } else if score > 0.0 {
            Severity::Low
        } else {
            Severity::Unknown
        }
    }

    /// Parses the text labels advisory databases use, such as GitHub's
    /// `"MODERATE"`. Returns `None` for anything we don't recognise.
    ///
    /// `Option<T>` is Rust's "maybe a value": either `Some(value)` or `None`.
    /// There is no `null`, so the compiler forces callers to handle `None`.
    pub fn from_label(label: &str) -> Option<Severity> {
        match label.to_ascii_uppercase().as_str() {
            "CRITICAL" => Some(Severity::Critical),
            "HIGH" => Some(Severity::High),
            "MODERATE" | "MEDIUM" => Some(Severity::Medium),
            "LOW" => Some(Severity::Low),
            _ => None,
        }
    }

    /// The upper-case label used in the text report.
    ///
    /// `&'static str` means "a string slice that lives for the whole program",
    /// which is exactly what string literals are, so no allocation happens.
    pub fn label(self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Unknown => "UNKNOWN",
        }
    }

    /// The lower-case name used in summaries ("3 high, 1 low").
    pub fn name(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Unknown => "unknown severity",
        }
    }
}

/// What kind of problem a finding describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingKind {
    /// A dependency version with a published security advisory.
    Vulnerability,
    /// A dependency known to be malware (OSV advisories with a `MAL-` ID).
    Malicious,
    /// A credential (API key, token, password...) committed to the repository.
    Secret,
}

/// A package from a lockfile or manifest.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct Package {
    pub name: String,
    pub version: String,
    /// The package ecosystem as OSV names it: "npm", "PyPI", "crates.io", ...
    pub ecosystem: String,
}

/// One problem found in the repository, whatever tool found it.
///
/// `#[serde(skip_serializing_if = ...)]` keeps the JSON output tidy by leaving
/// out empty fields instead of printing `null` or `[]`.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub kind: FindingKind,
    pub severity: Severity,
    /// The main identifier: the CVE when the advisory has one, otherwise the
    /// database's own ID (GHSA-..., PYSEC-..., MAL-...), or for secrets the
    /// gitleaks rule that matched (e.g. "github-pat").
    pub id: String,
    /// Every other identifier that refers to the same issue.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
    /// One-line human description.
    pub title: String,
    /// The file the finding is in, relative to the repository root.
    pub file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    /// The affected package (dependency findings only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package: Option<Package>,
    /// Versions in which the vulnerability is fixed (dependency findings only).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub fixed_in: Vec<String>,
    /// The lowest of `fixed_in` that's newer than the installed version, if
    /// it could be worked out: the version to upgrade to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upgrade_to: Option<String>,
    /// The commit that introduced the secret (secret findings only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    /// Where to read more.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// gitleaks' stable ID for a secret finding. Add it to
    /// `~/.config/git-vulnscan/.gitleaksignore` to silence a false positive.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}

/// Whether a scanner ran, and if not, why.
///
/// This is an enum whose variants carry data, which is one of Rust's most
/// useful features: a value is *either* `Ok`, *or* `Unavailable` with a
/// message, *or* `Failed` with a message, and `match` makes you handle each
/// case. The serde attributes turn it into
/// `{"status": "failed", "detail": "..."}` in JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", content = "detail", rename_all = "lowercase")]
pub enum ScannerStatus {
    Ok,
    /// The scanner binary couldn't be found.
    Unavailable(String),
    /// The scanner ran but exited with an error or printed something we
    /// couldn't parse.
    Failed(String),
}

/// The outcome of running one scanner.
#[derive(Debug, Clone, Serialize)]
pub struct ScannerRun {
    /// The tool's name, e.g. "osv-scanner".
    pub scanner: &'static str,
    /// What it checks, e.g. "dependencies".
    pub checks: &'static str,
    /// `flatten` inlines the status fields into this object in the JSON.
    #[serde(flatten)]
    pub status: ScannerStatus,
    /// How many findings this scanner reported.
    pub findings: usize,
}

/// Everything we learned from scanning one repository.
#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    pub repository: String,
    /// What was scanned, in words, e.g. "full scan" or "commits abc123..def456".
    pub scope: String,
    pub scanners: Vec<ScannerRun>,
    pub findings: Vec<Finding>,
}

/// The final verdict of a scan, which decides the process exit code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Nothing at or above the threshold, and every scanner ran.
    Pass,
    /// At least one finding at or above the threshold.
    Fail,
    /// Nothing at or above the threshold, but a scanner couldn't run, so we
    /// can't vouch for the repository.
    Incomplete,
}

/// Number of findings per severity.
///
/// `Default` gives us a zeroed instance via `Counts::default()`.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct Counts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub unknown: usize,
}

impl Counts {
    /// Counts findings per severity.
    ///
    /// Accepts anything that can be iterated as `&Finding`: a `&Vec<Finding>`,
    /// a slice, a filtered iterator... (`'a` ties the references to the data
    /// they borrow from.)
    pub fn tally<'a>(findings: impl IntoIterator<Item = &'a Finding>) -> Counts {
        let mut counts = Counts::default();
        for finding in findings {
            // `match` here returns a *mutable reference* to the right field,
            // and `+= 1` increments the field through that reference.
            let slot = match finding.severity {
                Severity::Critical => &mut counts.critical,
                Severity::High => &mut counts.high,
                Severity::Medium => &mut counts.medium,
                Severity::Low => &mut counts.low,
                Severity::Unknown => &mut counts.unknown,
            };
            *slot += 1;
        }
        counts
    }

    /// The count for one severity.
    pub fn get(&self, severity: Severity) -> usize {
        match severity {
            Severity::Critical => self.critical,
            Severity::High => self.high,
            Severity::Medium => self.medium,
            Severity::Low => self.low,
            Severity::Unknown => self.unknown,
        }
    }
}

impl ScanReport {
    /// Counts the findings per severity.
    pub fn counts(&self) -> Counts {
        Counts::tally(&self.findings)
    }

    /// True if any scanner didn't run successfully.
    pub fn is_incomplete(&self) -> bool {
        self.scanners
            .iter()
            .any(|run| run.status != ScannerStatus::Ok)
    }

    /// Decides pass/fail against the user's threshold.
    pub fn verdict(&self, fail_on: FailOn) -> Verdict {
        // `if let Some(x) = ...` runs the block only when the Option holds a
        // value, and binds that value to `x` inside the block.
        if let Some(threshold) = fail_on.threshold() {
            if self.findings.iter().any(|f| f.severity >= threshold) {
                return Verdict::Fail;
            }
        }
        if self.is_incomplete() {
            Verdict::Incomplete
        } else {
            Verdict::Pass
        }
    }
}

// Unit tests live next to the code they test, in a module that's only
// compiled when running `cargo test` (that's what `#[cfg(test)]` means).
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severities_are_ordered() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::Low > Severity::Unknown);
    }

    #[test]
    fn cvss_bands() {
        assert_eq!(Severity::from_cvss_score(9.8), Severity::Critical);
        assert_eq!(Severity::from_cvss_score(7.0), Severity::High);
        assert_eq!(Severity::from_cvss_score(5.3), Severity::Medium);
        assert_eq!(Severity::from_cvss_score(3.1), Severity::Low);
        assert_eq!(Severity::from_cvss_score(0.0), Severity::Unknown);
    }

    #[test]
    fn labels() {
        assert_eq!(Severity::from_label("MODERATE"), Some(Severity::Medium));
        assert_eq!(Severity::from_label("high"), Some(Severity::High));
        assert_eq!(Severity::from_label("whatever"), None);
    }
}
