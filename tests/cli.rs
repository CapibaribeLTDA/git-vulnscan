//! End-to-end tests: run the real `git-vulnscan` binary and real `git`
//! (hooks included) against throwaway repositories.
//!
//! Fake scanners stand in for osv-scanner and gitleaks: small shell scripts
//! that record the arguments they were called with and print a canned report
//! (the fixtures in `tests/fixtures/`). That keeps the tests fast, offline and
//! deterministic, and lets us check *how* the scanners are invoked, which is
//! where the security-relevant behaviour lives.
//!
//! Each test gets its own sandbox: a temporary HOME, global git config and
//! log folder, so the tests never touch your real `~/.gitconfig`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use tempfile::TempDir;

/// Path to the compiled binary. Cargo sets `CARGO_BIN_EXE_<name>` for
/// integration tests, and `env!` reads it at compile time.
const BIN: &str = env!("CARGO_BIN_EXE_git-vulnscan");

/// An isolated environment for one test.
struct Sandbox {
    /// Deleted (with everything inside) when the sandbox is dropped.
    root: TempDir,
}

impl Sandbox {
    fn new() -> Sandbox {
        let root = tempfile::tempdir().unwrap();
        let sandbox = Sandbox { root };
        for dir in ["home", "config", "bin", "logs"] {
            fs::create_dir_all(sandbox.path(dir)).unwrap();
        }
        fs::write(
            sandbox.path("gitconfig"),
            "[user]\n\tname = Test\n\temail = test@example.com\n\
             [init]\n\tdefaultBranch = main\n\
             [pull]\n\trebase = false\n\
             [advice]\n\tdetachedHead = false\n",
        )
        .unwrap();

        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        // The fake osv-scanner substitutes the repository path (its last
        // argument) into the fixture, and exits with 1 = "vulnerabilities found".
        sandbox.write_script(
            "osv-scanner",
            &format!(
                "printf '%s\\n' \"$*\" >> \"$FAKE_LOG_DIR/osv-scanner.log\"\n\
                 for last; do :; done\n\
                 sed \"s|__REPO__|$last|g\" '{}'\n\
                 exit 1\n",
                fixtures.join("osv-scanner.json").display()
            ),
        );
        sandbox.write_script(
            "gitleaks",
            &format!(
                "printf '%s\\n' \"$*\" >> \"$FAKE_LOG_DIR/gitleaks.log\"\n\
                 cat '{}'\n",
                fixtures.join("gitleaks.json").display()
            ),
        );
        sandbox
    }

    /// A path inside the sandbox.
    fn path(&self, relative: &str) -> PathBuf {
        self.root.path().join(relative)
    }

    fn write_script(&self, name: &str, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        let path = self.path("bin").join(name);
        fs::write(&path, format!("#!/bin/sh\n{body}")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// Applies the sandbox environment to a command.
    fn command(&self, program: &str, cwd: &Path) -> Command {
        let mut cmd = Command::new(program);
        cmd.current_dir(cwd)
            .env("HOME", self.path("home"))
            .env("XDG_CONFIG_HOME", self.path("config"))
            .env("GIT_CONFIG_GLOBAL", self.path("gitconfig"))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_VULNSCAN_OSV_SCANNER", self.path("bin/osv-scanner"))
            .env("GIT_VULNSCAN_GITLEAKS", self.path("bin/gitleaks"))
            .env("FAKE_LOG_DIR", self.path("logs"))
            .env("NO_COLOR", "1")
            // Make sure nothing from the environment running the tests leaks in.
            .env_remove("GIT_VULNSCAN_SKIP")
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_INDEX_FILE");
        cmd
    }

    fn git(&self, cwd: &Path, args: &[&str]) -> Output {
        let output = self.command("git", cwd).args(args).output().unwrap();
        assert!(output.status.success(), "git {args:?} failed:\n{}", text(&output));
        output
    }

    fn vulnscan(&self, cwd: &Path, args: &[&str]) -> Output {
        self.command(BIN, cwd).args(args).output().unwrap()
    }

    /// The argument lists the fake scanner was called with, one per call.
    fn calls(&self, tool: &str) -> Vec<String> {
        fs::read_to_string(self.path("logs").join(format!("{tool}.log")))
            .map(|log| log.lines().map(String::from).collect())
            .unwrap_or_default()
    }

    fn clear_calls(&self) {
        for tool in ["osv-scanner", "gitleaks"] {
            let _ = fs::remove_file(self.path("logs").join(format!("{tool}.log")));
        }
    }

    /// Creates a repository with a lockfile and one commit.
    fn repo(&self, name: &str) -> PathBuf {
        let repo = self.path(name);
        fs::create_dir_all(&repo).unwrap();
        self.git(&repo, &["init", "-q"]);
        fs::write(repo.join("package-lock.json"), "{}").unwrap();
        fs::write(repo.join("README.md"), "hello\n").unwrap();
        self.commit(&repo, "initial");
        repo
    }

    fn commit(&self, repo: &Path, message: &str) {
        self.git(repo, &["add", "-A"]);
        self.git(repo, &["commit", "-q", "-m", message]);
    }

    fn install_hooks(&self) {
        let output = self.vulnscan(&self.path("home"), &["install-hooks"]);
        assert!(output.status.success(), "install-hooks failed:\n{}", text(&output));
    }
}

/// stdout and stderr together, for assertions and failure messages.
fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn json(output: &Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).expect("stdout should be JSON")
}

// ---------------------------------------------------------------------------
// `git vulnscan scan`
// ---------------------------------------------------------------------------

#[test]
fn scan_reports_findings_and_fails() {
    let sandbox = Sandbox::new();
    let repo = sandbox.repo("project");

    let output = sandbox.vulnscan(&repo, &["scan", "--format", "json"]);
    assert_eq!(output.status.code(), Some(1), "{}", text(&output));

    let report = json(&output);
    assert_eq!(report["verdict"], "fail");
    let ids: Vec<&str> = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["id"].as_str().unwrap())
        .collect();
    for expected in ["MAL-2025-0001", "CVE-2021-35042", "CVE-2021-23337", "github-pat"] {
        assert!(ids.contains(&expected), "missing {expected} in {ids:?}");
    }
    // Sorted most severe first.
    assert_eq!(report["findings"][0]["severity"], "critical");
    assert_eq!(report["findings"][0]["file"], "package-lock.json");
}

#[test]
fn text_report_is_readable() {
    let sandbox = Sandbox::new();
    let repo = sandbox.repo("project");

    let output = sandbox.vulnscan(&repo, &["scan"]);
    let out = text(&output);
    assert!(out.contains("Known malicious packages"), "{out}");
    assert!(out.contains("lodash 4.17.15 (npm) · package-lock.json"), "{out}");
    assert!(out.contains("HIGH      CVE-2021-23337"), "{out}");
    assert!(out.contains("Command Injection in lodash · upgrade to 4.17.21"), "{out}");
    assert!(out.contains("config.env:1 · commit 7452bc1"), "{out}");
    assert!(out.contains("at or above the \"high\" threshold"), "{out}");
}

#[test]
fn fail_on_never_passes() {
    let sandbox = Sandbox::new();
    let repo = sandbox.repo("project");
    let output = sandbox.vulnscan(&repo, &["scan", "--fail-on", "never"]);
    assert_eq!(output.status.code(), Some(0), "{}", text(&output));
}

#[test]
fn fail_on_comes_from_git_config() {
    let sandbox = Sandbox::new();
    let repo = sandbox.repo("project");
    // Only gitleaks (high) and nothing critical once deps are skipped.
    sandbox.git(&repo, &["config", "vulnscan.failOn", "critical"]);
    let output = sandbox.vulnscan(&repo, &["scan", "--no-deps"]);
    assert_eq!(output.status.code(), Some(0), "{}", text(&output));
}

#[test]
fn scanners_ignore_the_repositorys_own_config() {
    let sandbox = Sandbox::new();
    let repo = sandbox.repo("project");
    sandbox.vulnscan(&repo, &["scan"]);

    let canonical_repo = repo.canonicalize().unwrap().display().to_string();

    let osv = &sandbox.calls("osv-scanner")[0];
    assert!(osv.contains("--no-ignore"), "{osv}");
    assert!(osv.contains("--config "), "{osv}");
    let gitleaks = &sandbox.calls("gitleaks")[0];
    for flag in ["--ignore-gitleaks-allow", "--redact", "--config ", "--gitleaks-ignore-path "] {
        assert!(gitleaks.contains(flag), "missing {flag}: {gitleaks}");
    }

    // The config and ignore paths must never point inside the repository.
    for call in [osv, gitleaks] {
        let words: Vec<&str> = call.split(' ').collect();
        for flag in ["--config", "--gitleaks-ignore-path"] {
            if let Some(i) = words.iter().position(|w| *w == flag) {
                let value = words[i + 1];
                assert!(!value.starts_with(&canonical_repo), "{flag} points into the repo: {value}");
                assert!(!value.starts_with(&repo.display().to_string()), "{flag} points into the repo: {value}");
            }
        }
    }
}

#[test]
fn user_allowlists_are_used() {
    let sandbox = Sandbox::new();
    let repo = sandbox.repo("project");
    let dir = sandbox.path("config/git-vulnscan");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("osv-scanner.toml"), "").unwrap();
    fs::write(dir.join(".gitleaksignore"), "").unwrap();

    sandbox.vulnscan(&repo, &["scan"]);
    let expected_osv = format!("--config {}", dir.join("osv-scanner.toml").display());
    assert!(sandbox.calls("osv-scanner")[0].contains(&expected_osv));
    let expected_ignore = format!("--gitleaks-ignore-path {}", dir.join(".gitleaksignore").display());
    assert!(sandbox.calls("gitleaks")[0].contains(&expected_ignore));
}

#[test]
fn missing_scanner_makes_the_scan_incomplete() {
    let sandbox = Sandbox::new();
    let repo = sandbox.repo("project");
    let output = sandbox
        .command(BIN, &repo)
        .env("GIT_VULNSCAN_OSV_SCANNER", "/nonexistent/osv-scanner")
        .args(["scan", "--fail-on", "never"])
        .output()
        .unwrap();
    // Exit code 2: we can't vouch for the repository.
    assert_eq!(output.status.code(), Some(2), "{}", text(&output));
    assert!(text(&output).contains("osv-scanner not found"));
}

#[test]
fn since_limits_the_secrets_scan() {
    let sandbox = Sandbox::new();
    let repo = sandbox.repo("project");
    fs::write(repo.join("b.txt"), "b").unwrap();
    sandbox.commit(&repo, "second");

    sandbox.vulnscan(&repo, &["scan", "--since", "HEAD~1"]);
    assert!(sandbox.calls("gitleaks")[0].contains("--log-opts "));
}

#[test]
fn outside_a_repository_is_an_error() {
    let sandbox = Sandbox::new();
    let output = sandbox.vulnscan(&sandbox.path("home"), &["scan"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(text(&output).contains("not inside a git repository"));
}

// ---------------------------------------------------------------------------
// Hooks: plain git commands trigger scans
// ---------------------------------------------------------------------------

#[test]
fn plain_git_clone_is_scanned() {
    let sandbox = Sandbox::new();
    let origin = sandbox.repo("origin");
    sandbox.install_hooks();

    let output = sandbox.git(&sandbox.path("."), &["clone", "-q", origin.to_str().unwrap(), "copy"]);
    let out = text(&output);
    assert!(out.contains("fresh clone"), "{out}");
    assert!(out.contains("CVE-2021-23337"), "{out}");
    // The report is compact in hooks: at most 5 advisories per package.
    assert_eq!(sandbox.calls("osv-scanner").len(), 1);
    let gitleaks = sandbox.calls("gitleaks");
    assert_eq!(gitleaks.len(), 1);
    assert!(!gitleaks[0].contains("--log-opts"), "a fresh clone scans the full history");
}

#[test]
fn git_pull_scans_only_what_changed() {
    let sandbox = Sandbox::new();
    let origin = sandbox.repo("origin");
    sandbox.install_hooks();
    sandbox.git(&sandbox.path("."), &["clone", "-q", origin.to_str().unwrap(), "copy"]);
    let copy = sandbox.path("copy");

    // A commit that doesn't touch dependencies: secrets scan of the new
    // commits only, no dependency scan.
    sandbox.clear_calls();
    fs::write(origin.join("README.md"), "changed\n").unwrap();
    sandbox.commit(&origin, "docs");
    let output = sandbox.git(&copy, &["pull", "-q"]);
    assert!(text(&output).contains("new commits pulled/merged"), "{}", text(&output));
    assert!(sandbox.calls("osv-scanner").is_empty());
    let gitleaks = sandbox.calls("gitleaks");
    assert_eq!(gitleaks.len(), 1);
    assert!(gitleaks[0].contains("--log-opts "), "{}", gitleaks[0]);

    // A commit that changes a lockfile: dependencies are rescanned.
    sandbox.clear_calls();
    fs::write(origin.join("package-lock.json"), "{\"changed\": true}").unwrap();
    sandbox.commit(&origin, "bump deps");
    sandbox.git(&copy, &["pull", "-q"]);
    assert_eq!(sandbox.calls("osv-scanner").len(), 1);
}

#[test]
fn git_pull_rebase_scans_once() {
    let sandbox = Sandbox::new();
    let origin = sandbox.repo("origin");
    sandbox.install_hooks();
    sandbox.git(&sandbox.path("."), &["clone", "-q", origin.to_str().unwrap(), "copy"]);
    let copy = sandbox.path("copy");

    // Diverge: a local commit, and an upstream commit touching dependencies.
    fs::write(copy.join("local.txt"), "mine").unwrap();
    sandbox.commit(&copy, "local work");
    fs::write(origin.join("package-lock.json"), "{\"changed\": true}").unwrap();
    sandbox.commit(&origin, "bump deps");

    sandbox.clear_calls();
    let output = sandbox.git(&copy, &["pull", "-q", "--rebase"]);
    // post-checkout fires mid-rebase and must be skipped; post-rewrite scans.
    assert_eq!(sandbox.calls("osv-scanner").len(), 1, "{}", text(&output));
    assert_eq!(sandbox.calls("gitleaks").len(), 1, "{}", text(&output));
    assert!(text(&output).contains("new commits rebased"), "{}", text(&output));
}

#[test]
fn switching_branches_rescans_only_when_dependencies_differ() {
    let sandbox = Sandbox::new();
    let repo = sandbox.repo("project");
    sandbox.install_hooks();

    sandbox.git(&repo, &["switch", "-q", "-c", "docs"]);
    fs::write(repo.join("README.md"), "docs\n").unwrap();
    sandbox.commit(&repo, "docs");
    sandbox.git(&repo, &["switch", "-q", "-c", "deps"]);
    fs::write(repo.join("package-lock.json"), "{\"v\": 2}").unwrap();
    sandbox.commit(&repo, "deps");

    sandbox.clear_calls();
    sandbox.git(&repo, &["switch", "-q", "docs"]); // lockfile differs
    assert_eq!(sandbox.calls("osv-scanner").len(), 1);
    sandbox.git(&repo, &["switch", "-q", "main"]); // only README differs
    assert_eq!(sandbox.calls("osv-scanner").len(), 1);
    assert!(sandbox.calls("gitleaks").is_empty());
}

#[test]
fn hooks_can_be_skipped_or_disabled() {
    let sandbox = Sandbox::new();
    let origin = sandbox.repo("origin");
    sandbox.install_hooks();

    // Skip once with the environment variable.
    let status = sandbox
        .command("git", &sandbox.path("."))
        .env("GIT_VULNSCAN_SKIP", "1")
        .args(["clone", "-q", origin.to_str().unwrap(), "skipped"])
        .status()
        .unwrap();
    assert!(status.success());
    assert!(sandbox.calls("osv-scanner").is_empty());

    // Disable for one repository with git config.
    let copy = sandbox.path("skipped");
    sandbox.git(&copy, &["config", "vulnscan.enabled", "false"]);
    fs::write(origin.join("package-lock.json"), "{\"changed\": true}").unwrap();
    sandbox.commit(&origin, "bump deps");
    sandbox.git(&copy, &["pull", "-q"]);
    assert!(sandbox.calls("osv-scanner").is_empty());
    assert!(sandbox.calls("gitleaks").is_empty());
}

#[test]
fn uninstall_removes_the_hooks() {
    let sandbox = Sandbox::new();
    let origin = sandbox.repo("origin");
    sandbox.install_hooks();
    let output = sandbox.vulnscan(&sandbox.path("home"), &["uninstall-hooks"]);
    assert!(text(&output).contains("Removed 3"), "{}", text(&output));

    sandbox.git(&sandbox.path("."), &["clone", "-q", origin.to_str().unwrap(), "copy"]);
    assert!(sandbox.calls("osv-scanner").is_empty());
    let config = fs::read_to_string(sandbox.path("gitconfig")).unwrap();
    assert!(!config.contains("vulnscan"), "{config}");
}

#[test]
fn a_failing_scanner_never_breaks_git() {
    let sandbox = Sandbox::new();
    let origin = sandbox.repo("origin");
    sandbox.install_hooks();
    sandbox.write_script("osv-scanner", "echo 'boom' >&2\nexit 127\n");

    // `sandbox.git` asserts that git succeeds.
    let output = sandbox.git(&sandbox.path("."), &["clone", "-q", origin.to_str().unwrap(), "copy"]);
    assert!(text(&output).contains("failed: osv-scanner exited"), "{}", text(&output));
}

#[test]
fn a_missing_binary_warns_but_never_breaks_git() {
    let sandbox = Sandbox::new();
    let origin = sandbox.repo("origin");
    // Install the hooks from a copy of the binary, then delete the copy.
    let copy = sandbox.path("bin/git-vulnscan-copy");
    fs::copy(BIN, &copy).unwrap();
    let output = sandbox.command(copy.to_str().unwrap(), &sandbox.path("home")).arg("install-hooks").output().unwrap();
    assert!(output.status.success(), "{}", text(&output));
    fs::remove_file(&copy).unwrap();

    let output = sandbox.git(&sandbox.path("."), &["clone", "-q", origin.to_str().unwrap(), "copy"]);
    assert!(text(&output).contains("warning: no scan, binary missing"), "{}", text(&output));
}

// ---------------------------------------------------------------------------
// `git vulnscan clone`, `doctor`, and running through git
// ---------------------------------------------------------------------------

#[test]
fn vulnscan_clone_scans_once_even_with_hooks() {
    let sandbox = Sandbox::new();
    let origin = sandbox.repo("origin");
    sandbox.install_hooks();

    // Run from another folder: the source repo already occupies "./origin".
    let output = sandbox.vulnscan(&sandbox.path("home"), &["clone", origin.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(1), "{}", text(&output));
    // Cloned into the folder named after the URL.
    assert!(sandbox.path("home/origin/.git").exists());
    assert_eq!(sandbox.calls("osv-scanner").len(), 1, "the hook must not scan a second time");
}

#[test]
fn doctor_reports_setup() {
    let sandbox = Sandbox::new();
    sandbox.install_hooks();
    let output = sandbox.vulnscan(&sandbox.path("home"), &["doctor"]);
    let out = text(&output);
    assert!(output.status.success(), "{out}");
    assert!(out.contains("✓ osv-scanner"), "{out}");
    assert!(out.contains("installed (global)"), "{out}");
}

#[test]
fn runs_as_a_git_subcommand() {
    let sandbox = Sandbox::new();
    // Put the binary's folder first on PATH, like `cargo install` would.
    let bin_dir = Path::new(BIN).parent().unwrap();
    let path = format!("{}:{}", bin_dir.display(), std::env::var("PATH").unwrap_or_default());
    let output = sandbox
        .command("git", &sandbox.path("home"))
        .env("PATH", path)
        .args(["vulnscan", "--version"])
        .output()
        .unwrap();
    assert!(text(&output).contains("git-vulnscan 0.1.0"), "{}", text(&output));
}
