//! Turning a [`ScanReport`] into text for humans or JSON for tools.

use anyhow::Result;
use serde::Serialize;

use crate::model::{Counts, Finding, FindingKind, ScanReport, ScannerStatus, Severity, Verdict};
use crate::scanners::{short, truncate};
use crate::settings::FailOn;

/// Options for the text report.
pub struct TextOptions {
    /// Use ANSI colours.
    pub color: bool,
    /// Show at most this many advisories per package. The hooks use a small
    /// number so a `git clone` doesn't flood the terminal; `None` shows all.
    pub max_per_package: Option<usize>,
    /// Show at most this many packages (the most severe ones).
    pub max_packages: Option<usize>,
    /// Print a single line when there's nothing to report (used by hooks,
    /// which run on every pull and shouldn't be chatty).
    pub compact: bool,
}

/// Decides whether to colour output written to a stream.
///
/// Respects the `NO_COLOR` convention (<https://no-color.org>) and never
/// colours output that goes to a file or pipe.
pub fn use_color(stream_is_terminal: bool) -> bool {
    let no_color = std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty());
    let dumb = std::env::var("TERM").is_ok_and(|term| term == "dumb");
    stream_is_terminal && !no_color && !dumb
}

/// Wraps text in ANSI escape codes when colour is enabled.
///
/// A struct with a single `bool` might look like overkill, but it lets us
/// write `style.red("text")` everywhere instead of passing the flag around.
struct Style {
    on: bool,
}

impl Style {
    fn paint(&self, text: &str, code: &str) -> String {
        if self.on {
            // "\x1b[" starts an escape sequence; "0m" resets all styles.
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    fn bold(&self, text: &str) -> String {
        self.paint(text, "1")
    }
    fn dim(&self, text: &str) -> String {
        self.paint(text, "2")
    }
    fn red(&self, text: &str) -> String {
        self.paint(text, "31")
    }
    fn green(&self, text: &str) -> String {
        self.paint(text, "32")
    }
    fn yellow(&self, text: &str) -> String {
        self.paint(text, "33")
    }

    /// The severity label, padded to a fixed width *before* colouring:
    /// escape codes are invisible but would still count towards the width.
    fn severity(&self, severity: Severity) -> String {
        let padded = format!("{:<8}", severity.label());
        let code = match severity {
            Severity::Critical => "1;31", // bold red
            Severity::High => "31",       // red
            Severity::Medium => "33",     // yellow
            Severity::Low => "34",        // blue
            Severity::Unknown => "2",     // dim
        };
        self.paint(&padded, code)
    }
}

/// Renders the human-readable report.
pub fn render_text(report: &ScanReport, fail_on: FailOn, options: &TextOptions) -> String {
    let style = Style { on: options.color };
    let verdict = report.verdict(fail_on);
    // `out` collects the whole report. `push_str` appends a `&str`, and
    // `format!` builds a `String` the same way `println!` prints one.
    let mut out = String::new();

    // Hooks: one quiet line when everything is fine.
    if options.compact && verdict == Verdict::Pass && report.findings.is_empty() {
        out.push_str(&format!(
            "git-vulnscan: {} no vulnerable dependencies or secrets found\n",
            style.green("✓")
        ));
        return out;
    }

    out.push_str(&format!(
        "\n{} {}\n",
        style.bold("git-vulnscan"),
        style.dim(&format!("· {} ({})", report.repository, report.scope))
    ));

    // One line per scanner, so it's obvious if something didn't run.
    for run in &report.scanners {
        let (mark, detail) = match &run.status {
            ScannerStatus::Ok => (style.green("✓"), plural(run.findings, "finding")),
            ScannerStatus::Unavailable(why) => (style.yellow("!"), style.yellow(&format!("not run: {why}"))),
            ScannerStatus::Failed(why) => (style.red("✗"), style.red(&format!("failed: {why}"))),
        };
        out.push_str(&format!("  {mark} {:<14}{:<13}{detail}\n", run.checks, run.scanner));
    }

    // `filter` keeps the items for which the closure returns true. We borrow
    // the findings (`&Finding`) rather than copying them.
    let malicious: Vec<&Finding> = report.findings.iter().filter(|f| f.kind == FindingKind::Malicious).collect();
    let vulnerable: Vec<&Finding> = report.findings.iter().filter(|f| f.kind == FindingKind::Vulnerability).collect();
    let secrets: Vec<&Finding> = report.findings.iter().filter(|f| f.kind == FindingKind::Secret).collect();

    if !malicious.is_empty() {
        // Malware is always shown in full, whatever the limits say.
        out.push_str(&format!("\n{}\n", style.red(&style.bold("Known malicious packages"))));
        render_packages(&mut out, &style, &malicious, None, None);
    }
    if !vulnerable.is_empty() {
        out.push_str(&format!("\n{}\n", style.bold("Vulnerable dependencies")));
        render_packages(&mut out, &style, &vulnerable, options.max_packages, options.max_per_package);
    }
    if !secrets.is_empty() {
        out.push_str(&format!("\n{}\n", style.bold("Secrets in git history")));
        for secret in &secrets {
            render_secret(&mut out, &style, secret);
        }
        out.push_str(&style.dim(
            "  False positive? Add its fingerprint (see --format json) to ~/.config/git-vulnscan/.gitleaksignore\n",
        ));
    }

    out.push('\n');
    out.push_str(&verdict_line(&style, report, fail_on, verdict));
    out.push('\n');
    out
}

/// Prints dependency findings grouped under their package.
fn render_packages(
    out: &mut String,
    style: &Style,
    findings: &[&Finding],
    max_packages: Option<usize>,
    max_per_package: Option<usize>,
) {
    let groups = group_by_package(findings);
    // `unwrap_or(usize::MAX)` means "no limit" when the Option is None.
    let package_count = max_packages.unwrap_or(usize::MAX).min(groups.len());

    for (heading, group) in &groups[..package_count] {
        out.push_str(&format!("  {}\n", style.bold(heading)));

        let shown = max_per_package.unwrap_or(usize::MAX).min(group.len());
        for finding in &group[..shown] {
            // The specific upgrade if we could work it out, else the raw list.
            // Matching on a tuple lets us look at both values at once.
            let fix = match (&finding.upgrade_to, finding.fixed_in.len()) {
                (Some(version), _) => format!(" · upgrade to {version}"),
                (None, 0) => String::new(),
                (None, 1..=3) => format!(" · fixed in {}", finding.fixed_in.join(", ")),
                (None, _) => format!(" · fixed in {}, …", finding.fixed_in[..3].join(", ")),
            };
            out.push_str(&format!(
                "    {}  {:<19}  {}{}\n",
                style.severity(finding.severity),
                finding.id,
                truncate(&finding.title, 70),
                style.dim(&fix)
            ));
        }

        let hidden = &group[shown..];
        if !hidden.is_empty() {
            out.push_str(&style.dim(&format!(
                "    … and {} more ({}). Run `git vulnscan scan` for the full list.\n",
                hidden.len(),
                // `copied()` turns the `&&Finding` items into `&Finding`.
                summarize(&Counts::tally(hidden.iter().copied()))
            )));
        }
    }

    let hidden_packages = &groups[package_count..];
    if !hidden_packages.is_empty() {
        // `flat_map` flattens each group's list of findings into one stream.
        let hidden_findings = hidden_packages.iter().flat_map(|(_, group)| group.iter().copied());
        out.push_str(&style.dim(&format!(
            "  … and {} more packages ({}). Run `git vulnscan scan` for the full list.\n",
            hidden_packages.len(),
            summarize(&Counts::tally(hidden_findings))
        )));
    }
}

/// Prints one secret finding.
fn render_secret(out: &mut String, style: &Style, secret: &Finding) {
    let location = match secret.line {
        Some(line) => format!("{}:{line}", secret.file),
        None => secret.file.clone(),
    };
    // `as_deref` turns `&Option<String>` into `Option<&str>`, which `map`
    // can then work with without moving the String out of the finding.
    let commit = secret
        .commit
        .as_deref()
        .map(|c| format!(" · commit {}", short(c)))
        .unwrap_or_default();
    out.push_str(&format!(
        "    {}  {:<19}  {location}{}\n",
        style.severity(secret.severity),
        secret.id,
        style.dim(&commit)
    ));
    out.push_str(&format!("    {:<8}  {:<19}  {}\n", "", "", style.dim(&truncate(&secret.title, 70))));
}

/// Groups findings by package (and file), most severe package first.
///
/// The return type borrows from the input: the `'a` lifetime says the
/// `&Finding` references in the result point into the same data as the
/// input slice, so the compiler won't let the result outlive it.
fn group_by_package<'a>(findings: &[&'a Finding]) -> Vec<(String, Vec<&'a Finding>)> {
    let mut groups: Vec<(String, Vec<&'a Finding>)> = Vec::new();
    for &finding in findings {
        let heading = match &finding.package {
            Some(p) => format!("{} {} ({}) · {}", p.name, p.version, p.ecosystem, finding.file),
            None => finding.file.clone(),
        };
        // `iter_mut().find(...)` gives a mutable reference to an existing
        // group if there is one, so we can push into it.
        match groups.iter_mut().find(|(h, _)| *h == heading) {
            Some((_, list)) => list.push(finding),
            None => groups.push((heading, vec![finding])),
        }
    }
    // The input is already sorted by severity, so each group's first entry is
    // its worst. Sort the groups by that, then by name.
    groups.sort_by(|(name_a, a), (name_b, b)| {
        b[0].severity.cmp(&a[0].severity).then_with(|| name_a.cmp(name_b))
    });
    groups
}

/// "2 critical, 5 high, 1 low": only the non-zero counts.
fn summarize(counts: &Counts) -> String {
    Severity::ALL_DESCENDING
        .iter()
        .filter(|&&severity| counts.get(severity) > 0)
        .map(|&severity| format!("{} {}", counts.get(severity), severity.name()))
        .collect::<Vec<_>>()
        .join(", ")
}

/// "1 finding" / "3 findings".
fn plural(n: usize, word: &str) -> String {
    if n == 1 { format!("1 {word}") } else { format!("{n} {word}s") }
}

/// The last line of the report: the verdict, in colour.
fn verdict_line(style: &Style, report: &ScanReport, fail_on: FailOn, verdict: Verdict) -> String {
    let counts = report.counts();
    let summary = summarize(&counts);
    match verdict {
        Verdict::Fail => style.red(&style.bold(&format!(
            "✗ {summary}: at or above the \"{}\" threshold",
            fail_on.name()
        ))),
        Verdict::Incomplete => style.yellow(&format!(
            "! Incomplete scan: not every scanner ran (see above).{}",
            if summary.is_empty() { String::new() } else { format!(" Found so far: {summary}.") }
        )),
        Verdict::Pass if report.findings.is_empty() => {
            style.green("✓ No vulnerable dependencies or secrets found")
        }
        Verdict::Pass => style.green(&format!(
            "✓ {summary}: all below the \"{}\" threshold",
            fail_on.name()
        )),
    }
}

/// The JSON report: the scan report plus a summary and the verdict.
///
/// `#[serde(flatten)]` merges the fields of `report` into this object
/// instead of nesting them under a "report" key. The `'a` lifetime lets the
/// struct borrow the report instead of copying it just to serialize it.
#[derive(Serialize)]
struct JsonReport<'a> {
    #[serde(flatten)]
    report: &'a ScanReport,
    summary: Counts,
    fail_on: FailOn,
    verdict: &'static str,
}

/// Renders the machine-readable report.
pub fn render_json(report: &ScanReport, fail_on: FailOn) -> Result<String> {
    let verdict = match report.verdict(fail_on) {
        Verdict::Pass => "pass",
        Verdict::Fail => "fail",
        Verdict::Incomplete => "incomplete",
    };
    let json = JsonReport { report, summary: report.counts(), fail_on, verdict };
    Ok(serde_json::to_string_pretty(&json)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Package, ScannerRun};

    fn finding(id: &str, severity: Severity, package: &str) -> Finding {
        Finding {
            kind: FindingKind::Vulnerability,
            severity,
            id: id.into(),
            aliases: Vec::new(),
            title: format!("Problem {id}"),
            file: "package-lock.json".into(),
            line: None,
            package: Some(Package { name: package.into(), version: "1.0.0".into(), ecosystem: "npm".into() }),
            fixed_in: vec!["1.0.1".into()],
            upgrade_to: None,
            commit: None,
            url: None,
            fingerprint: None,
        }
    }

    fn report(findings: Vec<Finding>) -> ScanReport {
        ScanReport {
            repository: "/repo".into(),
            scope: "dependencies".into(),
            scanners: vec![ScannerRun {
                scanner: "osv-scanner",
                checks: "dependencies",
                status: ScannerStatus::Ok,
                findings: findings.len(),
            }],
            findings,
        }
    }

    const PLAIN: TextOptions = TextOptions { color: false, max_per_package: None, max_packages: None, compact: false };

    #[test]
    fn groups_by_package_and_shows_verdict() {
        let r = report(vec![
            finding("CVE-1", Severity::Critical, "a"),
            finding("CVE-2", Severity::Low, "b"),
            finding("CVE-3", Severity::Low, "a"),
        ]);
        let text = render_text(&r, FailOn::High, &PLAIN);
        assert!(text.contains("a 1.0.0 (npm) · package-lock.json"));
        // Package "a" (critical) is listed before package "b" (low).
        assert!(text.find("a 1.0.0").unwrap() < text.find("b 1.0.0").unwrap());
        assert!(text.contains("CRITICAL  CVE-1"));
        assert!(text.contains("fixed in 1.0.1"));
        assert!(text.contains("✗ 1 critical, 2 low: at or above the \"high\" threshold"));
    }

    #[test]
    fn limits_findings_per_package() {
        let r = report((1..=4).map(|i| finding(&format!("CVE-{i}"), Severity::Medium, "a")).collect());
        let options = TextOptions { max_per_package: Some(2), ..PLAIN };
        let text = render_text(&r, FailOn::High, &options);
        assert!(text.contains("… and 2 more (2 medium)"));
        assert!(text.contains("✓ 4 medium: all below the \"high\" threshold"));
    }

    #[test]
    fn limits_packages() {
        let r = report(vec![
            finding("CVE-1", Severity::Critical, "a"),
            finding("CVE-2", Severity::High, "b"),
            finding("CVE-3", Severity::Low, "c"),
        ]);
        let options = TextOptions { max_packages: Some(1), ..PLAIN };
        let text = render_text(&r, FailOn::High, &options);
        assert!(text.contains("a 1.0.0"));
        assert!(!text.contains("b 1.0.0"));
        assert!(text.contains("… and 2 more packages (1 high, 1 low)"));
    }

    #[test]
    fn compact_when_clean() {
        let options = TextOptions { compact: true, ..PLAIN };
        let text = render_text(&report(Vec::new()), FailOn::High, &options);
        assert_eq!(text.trim(), "git-vulnscan: ✓ no vulnerable dependencies or secrets found");
    }

    #[test]
    fn json_has_summary_and_verdict() {
        let r = report(vec![finding("CVE-1", Severity::High, "a")]);
        let value: serde_json::Value = serde_json::from_str(&render_json(&r, FailOn::High).unwrap()).unwrap();
        assert_eq!(value["verdict"], "fail");
        assert_eq!(value["summary"]["high"], 1);
        assert_eq!(value["findings"][0]["id"], "CVE-1");
        assert_eq!(value["scanners"][0]["status"], "ok");
    }
}
