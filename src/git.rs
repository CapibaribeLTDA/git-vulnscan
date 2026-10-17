//! Small helpers for running `git` commands.
//!
//! We shell out to the `git` binary instead of using a git library: it's
//! simpler, always matches the user's git version and config, and is what
//! the hooks themselves are built on anyway.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

/// Runs `git -C <dir> <args...>` and returns its standard output.
///
/// The return type `Result<String>` (short for `anyhow::Result<String>`)
/// means "either `Ok(String)` or `Err(error)`". Inside the function, the `?`
/// operator unwraps an `Ok` or returns early with the `Err`, so error
/// handling stays out of the way of the main logic.
pub fn run(dir: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        // `.context(...)` wraps the underlying error with a message that says
        // what we were trying to do. Printing the error with `{:#}` shows
        // both: "failed to run git: No such file or directory".
        .context("failed to run git (is it installed?)")?;

    if !output.status.success() {
        // `bail!` is anyhow's shorthand for `return Err(anyhow!(...))`.
        bail!(
            "`git {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    // Command output is raw bytes. `from_utf8_lossy` decodes it as UTF-8,
    // replacing any invalid bytes instead of failing.
    Ok(String::from_utf8_lossy(&output.stdout).trim_end().to_string())
}

/// Like [`run`], but returns `None` instead of an error. For questions like
/// "does ORIG_HEAD exist?" where failure is a normal answer.
pub fn try_run(dir: &Path, args: &[&str]) -> Option<String> {
    run(dir, args).ok()
}

/// The root folder of the working tree that contains `dir`.
pub fn toplevel(dir: &Path) -> Result<PathBuf> {
    let root = run(dir, &["rev-parse", "--show-toplevel"])
        .with_context(|| format!("{} is not inside a git repository", dir.display()))?;
    Ok(PathBuf::from(root))
}

/// Resolves a revision (like `HEAD` or `ORIG_HEAD`) to a commit ID.
pub fn rev_parse(dir: &Path, rev: &str) -> Option<String> {
    // `--verify --quiet` makes git print nothing and exit non-zero if the
    // revision doesn't exist, instead of printing an error.
    try_run(dir, &["rev-parse", "--verify", "--quiet", &format!("{rev}^{{commit}}")])
}

/// The files that differ between two commits.
pub fn changed_files(dir: &Path, from: &str, to: &str) -> Result<Vec<String>> {
    let output = run(dir, &["diff", "--name-only", "--no-renames", from, to])?;
    // `.lines()` gives an iterator of `&str`; `.map(String::from)` turns each
    // borrowed slice into an owned `String`; `.collect()` builds the Vec.
    Ok(output.lines().map(String::from).collect())
}

/// True for the all-zeros commit ID git passes to hooks to mean "no commit".
/// `post-checkout` gets this as the previous HEAD right after a clone.
pub fn is_null_oid(oid: &str) -> bool {
    // Works for both SHA-1 (40 chars) and SHA-256 (64 chars) repositories.
    !oid.is_empty() && oid.chars().all(|c| c == '0')
}

/// True while a rebase is in progress. `git pull --rebase` triggers a
/// `post-checkout` in the middle of the rebase, which we skip because the
/// `post-rewrite` hook will handle the whole rebase once it's finished.
pub fn rebase_in_progress(dir: &Path) -> bool {
    ["rebase-merge", "rebase-apply"].iter().any(|name| {
        try_run(dir, &["rev-parse", "--git-path", name])
            // `--git-path` may print a path relative to `dir`.
            .map(|path| dir.join(path).exists())
            .unwrap_or(false)
    })
}

/// True if `dir` is a linked worktree (created with `git worktree add`)
/// rather than the repository's main checkout. A new worktree shares its
/// history with a repository we already scanned when it was cloned.
pub fn is_linked_worktree(dir: &Path) -> bool {
    let git_dir = try_run(dir, &["rev-parse", "--absolute-git-dir"]);
    let common_dir = try_run(dir, &["rev-parse", "--path-format=absolute", "--git-common-dir"]);
    // Comparing two `Option`s: both must be `Some` and differ.
    matches!((git_dir, common_dir), (Some(a), Some(b)) if a != b)
}

/// All config entries whose key starts with `<section>.`, in the order git
/// read them, as `(key, value)` pairs. Keys come back in lower case.
pub fn config_entries(dir: &Path, section: &str) -> Vec<(String, String)> {
    // `git config --get-regexp` exits with status 1 when nothing matches, so
    // treat any failure as "no entries".
    let Some(output) = try_run(dir, &["config", "--get-regexp", &format!(r"^{section}\.")]) else {
        return Vec::new();
    };
    // `let ... else` (above) is the mirror of `if let`: it binds the value or
    // runs the `else` block, which must leave the function.
    output
        .lines()
        .map(|line| {
            // Each line is "key value", or just "key" for a value-less boolean.
            match line.split_once(' ') {
                Some((key, value)) => (key.to_string(), value.to_string()),
                None => (line.to_string(), String::new()),
            }
        })
        .collect()
}

/// The folder name `git clone <url>` would pick: the last part of the URL,
/// without a trailing `.git`.
pub fn default_clone_dir(url: &str) -> String {
    let trimmed = url.trim_end_matches('/');
    let trimmed = trimmed.strip_suffix("/.git").unwrap_or(trimmed);
    // Split on `/` or `:` (for `git@github.com:user/repo.git`) and take the
    // last piece. An array of chars works as a "pattern" meaning "any of
    // these characters".
    let last = trimmed.rsplit(['/', ':']).next().unwrap_or(trimmed);
    let name = last.strip_suffix(".git").unwrap_or(last);
    if name.is_empty() { "repository".to_string() } else { name.to_string() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clone_dir_names() {
        assert_eq!(default_clone_dir("https://github.com/google/osv-scanner.git"), "osv-scanner");
        assert_eq!(default_clone_dir("git@github.com:user/repo.git"), "repo");
        assert_eq!(default_clone_dir("https://example.com/repo/"), "repo");
        assert_eq!(default_clone_dir("/srv/git/project/.git"), "project");
        assert_eq!(default_clone_dir("host:repo"), "repo");
    }

    #[test]
    fn null_oids() {
        assert!(is_null_oid("0000000000000000000000000000000000000000"));
        assert!(!is_null_oid("33e72009eaf72d722dac72440dedabc4507e99de"));
        assert!(!is_null_oid(""));
    }
}
