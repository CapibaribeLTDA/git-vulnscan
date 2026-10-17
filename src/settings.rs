//! User settings, read from `git config`.
//!
//! Instead of inventing our own config file, we store settings in git's own
//! configuration under the `vulnscan.` prefix. That gives us global defaults
//! (`git config --global vulnscan.failOn critical`) *and* per-repository
//! overrides (`git config vulnscan.enabled false` inside one repo) for free,
//! because git already merges system, global and local config for us.
//!
//! The one thing that does live in its own folder is the user's allowlists
//! for the scanners (see [`config_dir`]). They're deliberately kept **outside**
//! the repository: a cloned repo must never be able to tell the scanners to
//! ignore its own problems.

use std::path::{Path, PathBuf};

use clap::ValueEnum;
use serde::Serialize;

use crate::git;
use crate::model::Severity;

/// The severity at which a scan counts as failed (exit code 1).
///
/// Deriving `clap::ValueEnum` lets clap parse `--fail-on high` straight into
/// this enum, and generates the list of valid values for `--help`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FailOn {
    Critical,
    High,
    Medium,
    Low,
    /// Fail on any finding, including ones with unknown severity.
    Any,
    /// Never fail; just report.
    Never,
}

impl FailOn {
    /// The lowest severity that fails the scan, or `None` for "never fail".
    pub fn threshold(self) -> Option<Severity> {
        match self {
            FailOn::Critical => Some(Severity::Critical),
            FailOn::High => Some(Severity::High),
            FailOn::Medium => Some(Severity::Medium),
            FailOn::Low => Some(Severity::Low),
            FailOn::Any => Some(Severity::Unknown),
            FailOn::Never => None,
        }
    }

    /// The value's name as typed on the command line ("high", "never", ...).
    pub fn name(self) -> &'static str {
        match self {
            FailOn::Critical => "critical",
            FailOn::High => "high",
            FailOn::Medium => "medium",
            FailOn::Low => "low",
            FailOn::Any => "any",
            FailOn::Never => "never",
        }
    }
}

/// All settings, after merging git config with the built-in defaults.
///
/// Command-line flags are applied on top of these by the caller (see
/// `main.rs`), so the precedence is: flag > git config > default.
#[derive(Debug, Clone)]
pub struct Settings {
    /// `vulnscan.enabled`: set to false to turn the hooks off (globally, or
    /// for one repository).
    pub enabled: bool,
    /// `vulnscan.failOn`: see [`FailOn`].
    pub fail_on: FailOn,
    /// `vulnscan.deps`: scan dependencies with osv-scanner.
    pub deps: bool,
    /// `vulnscan.secrets`: scan for secrets with gitleaks.
    pub secrets: bool,
    /// `vulnscan.localDb`: download the OSV database and match locally,
    /// instead of sending the dependency list to the osv.dev API.
    pub local_db: bool,
    /// `vulnscan.osvScanner`: explicit path to the osv-scanner binary.
    pub osv_scanner: Option<PathBuf>,
    /// `vulnscan.gitleaks`: explicit path to the gitleaks binary.
    pub gitleaks: Option<PathBuf>,
}

// Implementing the standard `Default` trait documents the defaults in one
// place and lets us write `Settings::default()`.
impl Default for Settings {
    fn default() -> Self {
        Settings {
            enabled: true,
            fail_on: FailOn::High,
            deps: true,
            secrets: true,
            local_db: false,
            osv_scanner: None,
            gitleaks: None,
        }
    }
}

impl Settings {
    /// Reads the settings that apply in `dir` (global config, plus the local
    /// config of the repository `dir` is in, if any).
    ///
    /// This never fails: a bad value only prints a warning and keeps the
    /// default, because a typo in your config shouldn't stop `git clone`.
    pub fn load(dir: &Path) -> Settings {
        let mut settings = Settings::default();

        // Git prints keys in lower case, and lists values in the order it read
        // them (system, then global, then local). Applying them in order means
        // the last one wins, which is exactly git's own rule.
        for (key, value) in git::config_entries(dir, "vulnscan") {
            match key.as_str() {
                "vulnscan.enabled" => settings.enabled = parse_bool(&key, &value, settings.enabled),
                "vulnscan.deps" => settings.deps = parse_bool(&key, &value, settings.deps),
                "vulnscan.secrets" => settings.secrets = parse_bool(&key, &value, settings.secrets),
                "vulnscan.localdb" => settings.local_db = parse_bool(&key, &value, settings.local_db),
                // `FailOn::from_str` comes from the `ValueEnum` trait; `true`
                // means "ignore case". It returns a `Result`, and `.ok()`
                // turns that into an `Option`, discarding the error message.
                "vulnscan.failon" => match FailOn::from_str(&value, true).ok() {
                    Some(fail_on) => settings.fail_on = fail_on,
                    None => warn(&key, &value, "critical, high, medium, low, any or never"),
                },
                "vulnscan.osvscanner" => settings.osv_scanner = Some(expand_tilde(&value)),
                "vulnscan.gitleaks" => settings.gitleaks = Some(expand_tilde(&value)),
                _ => eprintln!("git-vulnscan: warning: unknown setting `{key}` in git config"),
            }
        }
        settings
    }
}

/// Parses a git-style boolean. Git accepts several spellings, and a key that's
/// present with no value at all (`[vulnscan] enabled`) means `true`.
fn parse_bool(key: &str, value: &str, default: bool) -> bool {
    match value.to_ascii_lowercase().as_str() {
        "" | "true" | "yes" | "on" | "1" => true,
        "false" | "no" | "off" | "0" => false,
        _ => {
            warn(key, value, "true or false");
            default
        }
    }
}

fn warn(key: &str, value: &str, expected: &str) {
    eprintln!("git-vulnscan: warning: ignoring {key}={value:?} (expected {expected})");
}

/// Expands a leading `~/` to the home directory, like the shell would.
fn expand_tilde(value: &str) -> PathBuf {
    // `strip_prefix` returns `Some(rest)` if the string starts with the
    // prefix. Combined with `if let`, it's a neat way to test-and-extract.
    if let Some(rest) = value.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(value)
}

/// The folder for the user's scanner allowlists:
/// `$XDG_CONFIG_HOME/git-vulnscan`, or `~/.config/git-vulnscan`.
///
/// Files the scanners will use from there, when present:
/// - `osv-scanner.toml`: osv-scanner config (e.g. vulnerabilities to ignore)
/// - `gitleaks.toml`: gitleaks config (custom rules or allowlists)
/// - `.gitleaksignore`: fingerprints of gitleaks findings to ignore
pub fn config_dir() -> Option<PathBuf> {
    // `var_os` returns `Option<OsString>`. `.filter(...)` turns an empty value
    // into `None`, and `.map(...)` converts the value if there is one. These
    // combinators let you transform an Option without writing `match`.
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))?;
    // The `?` above works on Options too: if both lookups gave `None`, the
    // function returns `None` right there.
    Some(base.join("git-vulnscan"))
}

/// The path of a file in [`config_dir`], if it exists.
pub fn user_file(name: &str) -> Option<PathBuf> {
    let path = config_dir()?.join(name);
    path.is_file().then_some(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn booleans() {
        assert!(parse_bool("k", "", false));
        assert!(parse_bool("k", "Yes", false));
        assert!(!parse_bool("k", "off", true));
        // Unparseable values keep the default.
        assert!(parse_bool("k", "maybe", true));
    }

    #[test]
    fn thresholds() {
        assert_eq!(FailOn::High.threshold(), Some(Severity::High));
        assert_eq!(FailOn::Any.threshold(), Some(Severity::Unknown));
        assert_eq!(FailOn::Never.threshold(), None);
    }
}
