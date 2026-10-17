//! Dependency scanning with osv-scanner.
//!
//! osv-scanner finds the lockfiles and manifests in a project (npm, PyPI,
//! Cargo, Go, Maven, RubyGems, ... and git submodules) and looks every
//! package version up in the OSV database (<https://osv.dev>). OSV merges
//! the GitHub Advisory Database, PyPA, RustSec, the Go vulnerability
//! database and others, and also lists known-malicious packages (`MAL-` IDs).

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use super::{ScanRequest, last_lines, relative_to};
use crate::model::{Finding, FindingKind, Package, Severity};
use crate::settings;

/// Folders we never descend into. They hold installed packages or virtual
/// environments, which are big, slow to walk, and duplicate what the
/// lockfiles already say.
const EXCLUDED_DIRS: &[&str] = &["node_modules", ".venv", "venv", ".tox"];

/// Runs osv-scanner on the repository and converts its report.
pub fn scan(binary: &Path, request: &ScanRequest) -> Result<Vec<Finding>> {
    // osv-scanner prints absolute, symlink-resolved paths. Resolving the repo
    // path the same way lets us turn them back into relative paths.
    // (On macOS, /tmp is a symlink to /private/tmp, for example.)
    let repo = request
        .repo
        .canonicalize()
        .with_context(|| format!("can't access {}", request.repo.display()))?;

    // SECURITY: osv-scanner automatically reads an `osv-scanner.toml` found
    // next to the lockfiles, and that file can tell it to ignore
    // vulnerabilities. A malicious repository could ship one to hide its own
    // problems. Passing `--config` explicitly disables that lookup. We pass
    // the user's own config if they have one, or an empty file otherwise.
    //
    // The temporary file is deleted when `empty_config` is *dropped*, which
    // happens automatically at the end of this function. That's why it must
    // stay in a variable until osv-scanner has finished (this pattern is
    // called RAII: cleanup tied to a value's lifetime).
    let empty_config = tempfile::Builder::new()
        .prefix("git-vulnscan-")
        .suffix(".toml")
        .tempfile()
        .context("couldn't create a temporary file")?;
    let config = settings::user_file("osv-scanner.toml")
        .unwrap_or_else(|| empty_config.path().to_path_buf());

    let mut command = Command::new(binary);
    command.args([
        "scan",
        "source",
        "--recursive",
        // SECURITY: by default osv-scanner skips files matched by
        // `.gitignore`. A repository can commit a lockfile *and* list it in
        // its own `.gitignore` to hide it from the scan, so we turn that off.
        "--no-ignore",
        // A repo without any lockfile is fine: report nothing, don't fail.
        "--allow-no-lockfiles",
        "--format",
        "json",
        "--verbosity",
        "error",
    ]);
    command.arg("--config").arg(&config);
    for dir in EXCLUDED_DIRS {
        command.args(["--x-exclude", dir]);
    }
    if request.local_db {
        // Download the vulnerability databases for the ecosystems in use and
        // match locally, so the list of dependencies never leaves the machine.
        command.args(["--offline-vulnerabilities", "--download-offline-databases"]);
    }
    command.arg(&repo);

    let output = command
        .output()
        .with_context(|| format!("failed to run {}", binary.display()))?;

    // osv-scanner's exit codes: 0 = no vulnerabilities, 1 = vulnerabilities
    // found, anything else = error. `Some(0 | 1)` matches either value.
    match output.status.code() {
        Some(0 | 1) => parse(&output.stdout, &repo),
        _ => bail!(
            "osv-scanner exited with {}: {}",
            output.status,
            last_lines(&output.stderr, 5)
        ),
    }
}

// ---------------------------------------------------------------------------
// The shape of osv-scanner's JSON output.
//
// We only declare the fields we use: serde ignores the rest by default.
// `#[serde(default)]` means "if the field is missing, use the type's default
// value" (empty string, empty Vec, None), which makes parsing tolerant of
// fields that some advisories leave out.
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct Output {
    #[serde(default)]
    results: Vec<SourceResult>,
}

/// The results for one lockfile.
#[derive(Debug, Deserialize)]
struct SourceResult {
    source: Source,
    #[serde(default)]
    packages: Vec<PackageResult>,
}

#[derive(Debug, Deserialize)]
struct Source {
    path: String,
}

/// One vulnerable package and its advisories.
#[derive(Debug, Deserialize)]
struct PackageResult {
    package: PackageInfo,
    #[serde(default)]
    vulnerabilities: Vec<Vulnerability>,
    /// osv-scanner groups advisories that describe the same issue: e.g. a
    /// PYSEC and a GHSA advisory for the same CVE end up in one group. We
    /// report one finding per group, so the same bug isn't listed twice.
    #[serde(default)]
    groups: Vec<Group>,
}

#[derive(Debug, Deserialize)]
struct PackageInfo {
    #[serde(default)]
    name: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    ecosystem: String,
    /// Set instead of name/version for git submodules.
    #[serde(default)]
    commit: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct Group {
    ids: Vec<String>,
    #[serde(default)]
    aliases: Vec<String>,
    /// The highest CVSS score among the group's advisories, as a string
    /// ("7.5"). Empty when none of them has a score.
    #[serde(default)]
    max_severity: String,
}

/// One OSV advisory. See <https://ossf.github.io/osv-schema/>.
#[derive(Debug, Deserialize)]
struct Vulnerability {
    id: String,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    details: String,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    affected: Vec<Affected>,
    /// Free-form data specific to the source database. GitHub advisories put
    /// a severity label ("HIGH", "MODERATE", ...) here. We keep it as an
    /// untyped `serde_json::Value` because its shape differs per database.
    #[serde(default)]
    database_specific: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct Affected {
    #[serde(default)]
    package: Option<AffectedPackage>,
    #[serde(default)]
    ranges: Vec<Range>,
}

#[derive(Debug, Deserialize)]
struct AffectedPackage {
    #[serde(default)]
    name: String,
}

/// A version range, described as a list of events like
/// `[{"introduced": "4.0.0"}, {"fixed": "4.17.21"}]`.
#[derive(Debug, Deserialize)]
struct Range {
    /// "SEMVER", "ECOSYSTEM" or "GIT". `type` is a Rust keyword, so the
    /// field gets another name and serde maps it back.
    #[serde(rename = "type", default)]
    kind: String,
    #[serde(default)]
    events: Vec<Event>,
}

#[derive(Debug, Deserialize)]
struct Event {
    #[serde(default)]
    fixed: Option<String>,
}

impl Vulnerability {
    /// The severity label from `database_specific.severity`, if present.
    fn label_severity(&self) -> Option<Severity> {
        // A chain of `?` on Options: if any step is missing, the whole
        // expression is `None`.
        let label = self.database_specific.as_ref()?.get("severity")?.as_str()?;
        Severity::from_label(label)
    }

    /// The advisory's summary, if it has one.
    fn summary(&self) -> Option<&str> {
        // `then_some` turns a bool into an Option: `Some(x)` if true.
        let summary = self.summary.trim();
        (!summary.is_empty()).then_some(summary)
    }

    /// The first line of the details. Used when no advisory in a group has a
    /// summary (PyPA advisories often don't).
    fn first_line_of_details(&self) -> Option<&str> {
        let line = self.details.lines().next()?.trim();
        (!line.is_empty()).then_some(line)
    }
}

/// Parses osv-scanner's JSON output into findings.
fn parse(json: &[u8], repo: &Path) -> Result<Vec<Finding>> {
    // `serde_json::from_slice` builds an `Output` from the bytes, guided by
    // the `Deserialize` implementations derived above.
    let output: Output =
        serde_json::from_slice(json).context("couldn't parse osv-scanner's JSON output")?;

    let mut findings = Vec::new();
    for result in &output.results {
        let file = relative_to(repo, &result.source.path);
        for package in &result.packages {
            for group in groups_of(package) {
                findings.push(to_finding(&group, package, &file));
            }
        }
    }
    Ok(findings)
}

/// The package's advisory groups. If osv-scanner didn't group them (older
/// versions), every advisory becomes its own group.
fn groups_of(package: &PackageResult) -> Vec<Group> {
    if !package.groups.is_empty() {
        return package.groups.clone();
    }
    package
        .vulnerabilities
        .iter()
        .map(|vuln| Group {
            ids: vec![vuln.id.clone()],
            aliases: vuln.aliases.clone(),
            max_severity: String::new(),
        })
        .collect()
}

/// Builds one [`Finding`] from an advisory group.
fn to_finding(group: &Group, package: &PackageResult, file: &str) -> Finding {
    // The full advisories that belong to this group.
    let vulns: Vec<&Vulnerability> = package
        .vulnerabilities
        .iter()
        .filter(|vuln| group.ids.contains(&vuln.id))
        .collect();

    // Every identifier for this issue, from both the group and its advisories.
    // A `BTreeSet` keeps them sorted and removes duplicates.
    let mut all_ids: std::collections::BTreeSet<String> =
        group.ids.iter().chain(&group.aliases).cloned().collect();
    for vuln in &vulns {
        all_ids.extend(vuln.aliases.iter().cloned());
    }

    let malicious = all_ids.iter().any(|id| id.starts_with("MAL-"));

    // Severity: malware is always critical. Otherwise use the CVSS score,
    // and fall back to the advisories' text labels.
    let severity = if malicious {
        Severity::Critical
    } else {
        group
            .max_severity
            .trim()
            // `parse::<f64>()` returns a Result; `.ok()` makes it an Option.
            .parse::<f64>()
            .ok()
            .map(Severity::from_cvss_score)
            .filter(|severity| *severity != Severity::Unknown)
            .or_else(|| vulns.iter().filter_map(|vuln| vuln.label_severity()).max())
            .unwrap_or(Severity::Unknown)
    };

    // Prefer the CVE as the main ID, since it's what people search for.
    let id = all_ids
        .iter()
        .find(|id| id.starts_with("CVE-"))
        .or_else(|| group.ids.first())
        .cloned()
        .unwrap_or_else(|| "unknown".to_string());
    all_ids.remove(&id);

    // Any advisory's summary beats a line of details.
    let title = vulns
        .iter()
        .find_map(|vuln| vuln.summary())
        .or_else(|| vulns.iter().find_map(|vuln| vuln.first_line_of_details()))
        .unwrap_or("No description available")
        .to_string();

    // The versions in which this is fixed, from the advisories' ranges for
    // this package. PyPI names aren't case-sensitive, so compare lower-case.
    let mut fixed_in: Vec<String> = Vec::new();
    let package_name = package.package.name.to_lowercase();
    for affected in vulns.iter().flat_map(|vuln| &vuln.affected) {
        let same_package = affected
            .package
            .as_ref()
            .is_some_and(|p| p.name.to_lowercase() == package_name);
        if !same_package {
            continue;
        }
        let fixed_versions = affected
            .ranges
            .iter()
            // "GIT" ranges list commit hashes, not versions you can install.
            .filter(|range| range.kind != "GIT")
            .flat_map(|range| &range.events)
            .filter_map(|event| event.fixed.as_ref());
        for fixed in fixed_versions {
            if !fixed_in.contains(fixed) {
                fixed_in.push(fixed.clone());
            }
        }
    }
    let upgrade_to = lowest_fix_above(&package.package.version, &fixed_in).map(String::from);

    Finding {
        kind: if malicious { FindingKind::Malicious } else { FindingKind::Vulnerability },
        severity,
        url: group.ids.first().map(|first| format!("https://osv.dev/vulnerability/{first}")),
        id,
        aliases: all_ids.into_iter().collect(),
        title,
        file: file.to_string(),
        line: None,
        package: Some(package_of(&package.package)),
        fixed_in,
        upgrade_to,
        commit: None,
        fingerprint: None,
    }
}

/// Picks the smallest fixed version that is newer than the installed one.
///
/// Advisories list one fix per release line ("fixed in 4.0.4, 3.2.13,
/// 2.2.28"); if you have 3.2.0, the useful answer is 3.2.13. Returns `None`
/// when the versions don't look like dotted numbers, in which case the
/// report shows the full list instead.
fn lowest_fix_above<'a>(installed: &str, fixed: &'a [String]) -> Option<&'a str> {
    let current = version_key(installed)?;
    fixed
        .iter()
        // Pair each version with its numeric key, dropping unparseable ones.
        .filter_map(|v| version_key(v).map(|key| (key, v.as_str())))
        .filter(|(key, _)| *key > current)
        // `min_by` with a comparison of the keys finds the lowest version.
        .min_by(|(a, _), (b, _)| a.cmp(b))
        .map(|(_, version)| version)
}

/// Turns "v1.20.3" into `[1, 20, 3]` so versions compare numerically
/// (as text, "1.10" < "1.9"). `Vec<u64>` compares element by element, which
/// is exactly version ordering. This is a heuristic: it ignores pre-release
/// tags like "-beta", but works for the plain releases fixes are listed as.
fn version_key(version: &str) -> Option<Vec<u64>> {
    let version = version.trim().trim_start_matches('v');
    let mut parts = Vec::new();
    for part in version.split('.') {
        // Keep the leading digits of each part: "0-beta" -> 0.
        let digits: String = part.chars().take_while(char::is_ascii_digit).collect();
        if digits.is_empty() {
            break;
        }
        parts.push(digits.parse().ok()?);
    }
    (!parts.is_empty()).then_some(parts)
}

/// Converts osv-scanner's package info into our [`Package`].
fn package_of(info: &PackageInfo) -> Package {
    match (&info.commit, info.name.is_empty()) {
        // Git submodules have a commit instead of a name and version.
        (Some(commit), true) => Package {
            name: "git submodule".to_string(),
            version: super::short(commit).to_string(),
            ecosystem: "git".to_string(),
        },
        _ => Package {
            name: info.name.clone(),
            version: info.version.clone(),
            ecosystem: info.ecosystem.clone(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Trimmed-down real osv-scanner output, with a made-up malicious
    /// package added. `include_str!` embeds the file at compile time.
    fn fixture() -> Vec<Finding> {
        let json = include_str!("../../tests/fixtures/osv-scanner.json").replace("__REPO__", "/repo");
        parse(json.as_bytes(), Path::new("/repo")).expect("fixture should parse")
    }

    /// Finds the finding with the given ID, or fails the test.
    fn by_id<'a>(findings: &'a [Finding], id: &str) -> &'a Finding {
        findings
            .iter()
            .find(|f| f.id == id)
            .unwrap_or_else(|| panic!("no finding with id {id}"))
    }

    #[test]
    fn one_finding_per_group() {
        // 2 lodash groups + 2 django groups + 1 malicious package.
        assert_eq!(fixture().len(), 5);
    }

    #[test]
    fn uses_cve_ids_and_relative_paths() {
        let findings = fixture();
        let lodash = by_id(&findings, "CVE-2021-23337");
        assert_eq!(lodash.file, "package-lock.json");
        assert_eq!(lodash.severity, Severity::High); // CVSS 7.2
        assert_eq!(lodash.title, "Command Injection in lodash");
        assert_eq!(lodash.fixed_in, ["4.17.21"]);
        assert!(lodash.aliases.contains(&"GHSA-35jh-r3h4-6jhm".to_string()));
        let package = lodash.package.as_ref().unwrap();
        assert_eq!((package.name.as_str(), package.ecosystem.as_str()), ("lodash", "npm"));
    }

    #[test]
    fn merges_grouped_advisories() {
        // This group holds a PYSEC advisory (no summary) and a GHSA one.
        let findings = fixture();
        let django = by_id(&findings, "CVE-2021-35042");
        assert_eq!(django.severity, Severity::Critical); // CVSS 9.8
        assert_eq!(django.file, "requirements.txt");
        assert_eq!(django.title, "SQL Injection in Django");
        // Fix versions from both advisories, without duplicates.
        assert_eq!(django.fixed_in, ["3.1.13", "3.2.5"]);
        assert!(django.aliases.contains(&"PYSEC-2021-109".to_string()));
    }

    #[test]
    fn suggests_the_fix_on_the_installed_release_line() {
        let fixed: Vec<String> = ["4.0.4", "3.2.13", "2.2.28"].map(String::from).to_vec();
        assert_eq!(lowest_fix_above("3.2.0", &fixed), Some("3.2.13"));
        assert_eq!(lowest_fix_above("4.0.0", &fixed), Some("4.0.4"));
        // Numeric comparison, not text: 1.10 is newer than 1.9.
        let fixed: Vec<String> = ["1.10.0", "1.9.1"].map(String::from).to_vec();
        assert_eq!(lowest_fix_above("1.9.5", &fixed), Some("1.10.0"));
        assert_eq!(lowest_fix_above("v1.2.3", &["v1.2.4".to_string()]), Some("v1.2.4"));
        // Nothing newer, or nothing comparable.
        assert_eq!(lowest_fix_above("5.0.0", &["4.0.0".to_string()]), None);
        assert_eq!(lowest_fix_above("abc", &["1.0".to_string()]), None);
    }

    #[test]
    fn django_fixture_suggests_upgrade() {
        let findings = fixture();
        assert_eq!(by_id(&findings, "CVE-2021-35042").upgrade_to.as_deref(), Some("3.2.5"));
    }

    #[test]
    fn details_are_the_title_fallback() {
        let vuln = Vulnerability {
            id: "PYSEC-1".into(),
            summary: String::new(),
            details: "First line.\nMore text.".into(),
            aliases: Vec::new(),
            affected: Vec::new(),
            database_specific: None,
        };
        assert_eq!(vuln.summary(), None);
        assert_eq!(vuln.first_line_of_details(), Some("First line."));
    }

    #[test]
    fn malicious_packages_are_critical() {
        let findings = fixture();
        let malware = by_id(&findings, "MAL-2025-0001");
        assert_eq!(malware.kind, FindingKind::Malicious);
        assert_eq!(malware.severity, Severity::Critical);
    }

    #[test]
    fn label_severity_is_the_fallback() {
        // This group has no CVSS score, only GitHub's "LOW" label.
        let findings = fixture();
        assert_eq!(by_id(&findings, "CVE-2026-48588").severity, Severity::Low);
    }
}
