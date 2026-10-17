//! Running the external scanners.
//!
//! git-vulnscan doesn't detect anything itself. It orchestrates two
//! well-established open source tools and merges their results:
//!
//! - [`osv`]: **osv-scanner** (Google) checks lockfiles against the OSV
//!   vulnerability database, which also lists known-malicious packages.
//! - [`gitleaks`]: **gitleaks** looks for committed credentials across the
//!   whole git history.
//!
//! Both scanners run at the same time on separate threads.

pub mod gitleaks;
pub mod osv;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;

use anyhow::Result;

use crate::model::{Finding, ScanReport, ScannerRun, ScannerStatus};
use crate::settings::Settings;

/// Which part of the git history to search for secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretsScope {
    /// Don't look for secrets.
    Off,
    /// Every commit reachable in the repository.
    FullHistory,
    /// Only the commits in `from..to` (e.g. what a `git pull` brought in).
    Range { from: String, to: String },
}

/// What to scan, decided by the command or hook that started the scan.
#[derive(Debug, Clone)]
pub struct ScanRequest {
    /// The repository's root folder.
    pub repo: PathBuf,
    /// Whether to run the dependency scan.
    pub deps: bool,
    /// Whether, and how much of the history, to search for secrets.
    pub secrets: SecretsScope,
    /// Use a locally downloaded vulnerability database (see `Settings`).
    pub local_db: bool,
}

impl ScanRequest {
    /// A short description of the scan for the report header.
    pub fn scope(&self) -> String {
        match &self.secrets {
            SecretsScope::Range { from, to } => {
                format!("commits {}..{}", short(from), short(to))
            }
            SecretsScope::FullHistory if self.deps => "dependencies and full history".into(),
            SecretsScope::FullHistory => "full history".into(),
            SecretsScope::Off => "dependencies".into(),
        }
    }
}

/// Abbreviates a commit ID to 7 characters, like git does.
pub fn short(oid: &str) -> &str {
    // `get(..7)` returns `None` instead of panicking if the string is shorter.
    oid.get(..7).unwrap_or(oid)
}

/// Describes an external scanner and how to find its binary.
pub struct Tool {
    /// The binary's name, also used to look it up on the PATH.
    pub name: &'static str,
    /// What it checks, for messages ("dependencies", "secrets").
    pub checks: &'static str,
    /// Environment variable that overrides the binary's location. The tests
    /// use it to substitute fake scanners.
    pub env_var: &'static str,
    /// Arguments that make it print its version.
    pub version_args: &'static [&'static str],
    /// Shown when the binary can't be found.
    pub install_hint: &'static str,
}

pub const OSV_SCANNER: Tool = Tool {
    name: "osv-scanner",
    checks: "dependencies",
    env_var: "GIT_VULNSCAN_OSV_SCANNER",
    version_args: &["--version"],
    install_hint: "brew install osv-scanner  (or: go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest)",
};

pub const GITLEAKS: Tool = Tool {
    name: "gitleaks",
    checks: "secrets",
    env_var: "GIT_VULNSCAN_GITLEAKS",
    version_args: &["version"],
    install_hint: "brew install gitleaks  (or: go install github.com/zricethezav/gitleaks/v8@latest)",
};

impl Tool {
    /// Finds the binary. Lookup order:
    /// 1. the tool's environment variable,
    /// 2. the path configured in git config,
    /// 3. the PATH,
    /// 4. common install folders. Git GUIs and editors are often started
    ///    with a minimal PATH that's missing e.g. `/opt/homebrew/bin`, and we
    ///    don't want the hooks to silently stop working there.
    pub fn locate(&self, configured: Option<&Path>) -> Option<PathBuf> {
        if let Some(path) = std::env::var_os(self.env_var).filter(|v| !v.is_empty()) {
            let path = PathBuf::from(path);
            return is_executable(&path).then_some(path);
        }
        if let Some(path) = configured {
            return is_executable(path).then(|| path.to_path_buf());
        }

        let mut dirs: Vec<PathBuf> = std::env::var_os("PATH")
            // `split_paths` splits on `:` (or `;` on Windows) for us.
            .map(|paths| std::env::split_paths(&paths).collect())
            .unwrap_or_default();
        dirs.extend(["/opt/homebrew/bin", "/usr/local/bin"].map(PathBuf::from));
        if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
            dirs.push(home.join("go/bin"));
            dirs.push(home.join(".local/bin"));
        }

        // `find_map` returns the first `Some` produced by the closure.
        dirs.into_iter().find_map(|dir| {
            let candidate = dir.join(self.name);
            is_executable(&candidate).then_some(candidate)
        })
    }

    /// The tool's version string, e.g. "2.7.0", if it can be determined.
    pub fn version(&self, binary: &Path) -> Option<String> {
        let output = Command::new(binary).args(self.version_args).output().ok()?;
        let text = String::from_utf8_lossy(&output.stdout);
        let first_line = text.lines().next()?.trim();
        // osv-scanner prints "osv-scanner version: 2.7.0"; keep the last word.
        first_line.rsplit(' ').next().map(String::from)
    }
}

/// True if `path` is a file we're allowed to execute.
fn is_executable(path: &Path) -> bool {
    // Code inside `#[cfg(unix)]` is only compiled on Unix-like systems, where
    // the "executable" permission bits exist.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        path.metadata()
            .map(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        path.is_file()
    }
}

/// Runs the requested scanners in parallel and collects their results.
pub fn scan(request: &ScanRequest, settings: &Settings) -> ScanReport {
    // `thread::scope` creates a scope in which spawned threads may *borrow*
    // local variables (`request`, `settings`). Plain `thread::spawn` can't do
    // that, because the compiler can't prove the thread finishes before the
    // borrowed data goes away. A scope guarantees it: every thread spawned in
    // it is joined before `scope` returns.
    let results: Vec<(ScannerRun, Vec<Finding>)> = thread::scope(|s| {
        let mut handles = Vec::new();

        if request.deps {
            handles.push(s.spawn(|| {
                run_tool(&OSV_SCANNER, settings.osv_scanner.as_deref(), |binary| {
                    osv::scan(binary, request)
                })
            }));
        }
        if request.secrets != SecretsScope::Off {
            handles.push(s.spawn(|| {
                run_tool(&GITLEAKS, settings.gitleaks.as_deref(), |binary| {
                    gitleaks::scan(binary, request)
                })
            }));
        }

        handles
            .into_iter()
            // `join` returns `Err` only if the thread panicked (crashed).
            // Re-raising that panic here is the right call: it's a bug.
            .map(|handle| handle.join().expect("scanner thread panicked"))
            .collect()
    });

    // Split the (run, findings) pairs into two lists.
    let mut scanners = Vec::new();
    let mut findings = Vec::new();
    for (run, mut found) in results {
        scanners.push(run);
        // `append` moves all elements out of `found` into `findings`.
        findings.append(&mut found);
    }

    // Most severe first; ties broken by file, then ID, so the output order is
    // stable from run to run. `cmp` returns an `Ordering` (Less/Equal/
    // Greater), and `then_with` only consults the next key on a tie.
    // Comparing `b` to `a` (instead of `a` to `b`) sorts in descending order.
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.id.cmp(&b.id))
    });

    ScanReport {
        repository: request.repo.display().to_string(),
        scope: request.scope(),
        scanners,
        findings,
    }
}

/// Locates `tool` and calls `scan_with` with its path, turning every way this
/// can go wrong into a [`ScannerStatus`] instead of an error. One scanner
/// failing shouldn't throw away the other scanner's results.
///
/// `F: FnOnce(&Path) -> Result<Vec<Finding>>` is a *generic* parameter: the
/// caller can pass any closure taking a path and returning findings.
/// `FnOnce` means we promise to call it at most once.
fn run_tool<F>(tool: &Tool, configured: Option<&Path>, scan_with: F) -> (ScannerRun, Vec<Finding>)
where
    F: FnOnce(&Path) -> Result<Vec<Finding>>,
{
    let (status, findings) = match tool.locate(configured) {
        None => (
            ScannerStatus::Unavailable(format!(
                "{} not found; install it with: {}",
                tool.name, tool.install_hint
            )),
            Vec::new(),
        ),
        Some(binary) => match scan_with(&binary) {
            Ok(findings) => (ScannerStatus::Ok, findings),
            // `{:#}` prints the error together with its context chain.
            Err(err) => (ScannerStatus::Failed(format!("{err:#}")), Vec::new()),
        },
    };

    let run = ScannerRun {
        scanner: tool.name,
        checks: tool.checks,
        status,
        findings: findings.len(),
    };
    (run, findings)
}

/// Turns an absolute path printed by a scanner into one relative to the
/// repository root, for readable output. Falls back to the original path.
pub fn relative_to(repo: &Path, path: &str) -> String {
    Path::new(path)
        .strip_prefix(repo)
        .map(|rel| rel.display().to_string())
        .unwrap_or_else(|_| path.to_string())
}

/// The last `n` non-empty lines of a scanner's error output, joined with
/// " | ", for compact error messages.
pub fn last_lines(bytes: &[u8], n: usize) -> String {
    let text = String::from_utf8_lossy(bytes);
    let lines: Vec<&str> = text.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    if lines.is_empty() {
        return "(no error output)".to_string();
    }
    // `saturating_sub` stops at 0 instead of underflowing (usize can't be
    // negative, and in debug builds an underflow would panic).
    lines[lines.len().saturating_sub(n)..].join(" | ")
}

/// Shortens `text` to at most `max` characters, adding "…" if it was cut.
///
/// Rust strings are UTF-8, so a "character" can take several bytes. Slicing
/// with `&text[..max]` counts *bytes* and would panic in the middle of a
/// multi-byte character. Counting with `.chars()` is always safe.
pub fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut cut: String = text.chars().take(max.saturating_sub(1)).collect();
    cut.push('…');
    cut
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncates_by_characters() {
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("abcdefgh", 5), "abcd…");
        // Multi-byte characters don't cause a panic.
        assert_eq!(truncate("ação ação", 4), "açã…");
    }

    #[test]
    fn relative_paths() {
        let repo = Path::new("/work/repo");
        assert_eq!(relative_to(repo, "/work/repo/web/package-lock.json"), "web/package-lock.json");
        assert_eq!(relative_to(repo, "/elsewhere/x"), "/elsewhere/x");
    }
}
