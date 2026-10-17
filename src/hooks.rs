//! Automatic scanning through git hooks.
//!
//! Git won't let an alias replace a built-in command, so `git clone` can't be
//! aliased to `git vulnscan clone`. Hooks get the same result: git runs them
//! *after* its own work is done, so plain `git clone` (from a terminal, an
//! editor or a GUI) scans the new repository without you having to remember.
//!
//! We use **config-based hooks** (`hook.<name>.command` in git config, a
//! recent git feature) rather than scripts in `.git/hooks/`:
//!
//! - one entry in your global `~/.gitconfig` covers *every* repository,
//!   including ones cloned before installing;
//! - they run *alongside* each repository's own hooks instead of replacing
//!   them (which `core.hooksPath` would do).
//!
//! The events we listen to:
//!
//! | event           | when                              | what we scan                          |
//! |-----------------|-----------------------------------|---------------------------------------|
//! | `post-checkout` | end of `git clone`                | dependencies + full history           |
//! | `post-checkout` | branch switch                     | dependencies, if dependency files changed |
//! | `post-merge`    | `git pull` / `git merge`          | new commits, + deps if they changed   |
//! | `post-rewrite`  | `git pull --rebase` / `git rebase`| same as post-merge                    |
//!
//! A hook never fails the git command: the clone has already happened, so the
//! most useful thing we can do is report loudly.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};

use crate::depfiles;
use crate::git;
use crate::report::{self, TextOptions};
use crate::scanners::{self, ScanRequest, SecretsScope};
use crate::settings::Settings;

/// Set this environment variable (to anything) to skip the hooks once:
/// `GIT_VULNSCAN_SKIP=1 git clone ...`. `git vulnscan clone` also sets it,
/// because it runs its own scan after cloning.
pub const SKIP_ENV: &str = "GIT_VULNSCAN_SKIP";

/// Our hooks, as (friendly name, git event) pairs. The friendly name is the
/// `<name>` in `hook.<name>.command`; git requires it to differ from the
/// event name.
pub const HOOKS: [(&str, &str); 3] = [
    ("vulnscan-checkout", "post-checkout"),
    ("vulnscan-merge", "post-merge"),
    ("vulnscan-rewrite", "post-rewrite"),
];

/// Writes the hook entries to the global git config (or, with `local`, to
/// the current repository's config).
pub fn install(local: bool) -> Result<()> {
    let cwd = std::env::current_dir()?;
    if local {
        git::toplevel(&cwd)?; // fails with a clear message outside a repo
    }
    // The absolute path of the running binary. Using it (instead of relying
    // on PATH) keeps the hooks working in GUIs started with a minimal PATH.
    let exe = std::env::current_exe()
        .and_then(|path| path.canonicalize())
        .context("couldn't determine the path of the git-vulnscan binary")?;
    let scope = scope_flag(local);

    for (name, event) in HOOKS {
        git::run(&cwd, &["config", scope, &format!("hook.{name}.command"), &hook_command(&exe, event)])?;
        // `--replace-all` because `event` can have several values; this makes
        // re-running `install-hooks` idempotent.
        git::run(&cwd, &["config", scope, "--replace-all", &format!("hook.{name}.event"), event])?;
    }

    // Check that git actually picks the hook up. Older git versions accept
    // the config keys but ignore them.
    let listed = git::try_run(&cwd, &["hook", "list", "post-checkout"]).unwrap_or_default();
    if !listed.lines().any(|line| line.trim() == HOOKS[0].0) {
        bail!(
            "the hooks were written to git config, but `git hook list post-checkout` doesn't show them. \
             Config-based hooks need a recent git; check `git --version` and upgrade git."
        );
    }

    let place = if local { "this repository's git config" } else { "your global git config" };
    println!("Installed git-vulnscan hooks in {place}.");
    println!("From now on, `git clone`, `git pull` and branch switches are scanned automatically.");
    println!("  Skip once:              GIT_VULNSCAN_SKIP=1 git clone ...");
    println!("  Disable in one repo:    git config vulnscan.enabled false");
    println!("  Remove:                 git vulnscan uninstall-hooks{}", if local { " --local" } else { "" });
    Ok(())
}

/// Removes the hook entries written by [`install`].
pub fn uninstall(local: bool) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let mut removed = 0;
    for (name, _) in HOOKS {
        // `--remove-section` fails if the section doesn't exist, which is
        // fine: there's nothing to remove.
        if git::try_run(&cwd, &["config", scope_flag(local), "--remove-section", &format!("hook.{name}")]).is_some() {
            removed += 1;
        }
    }
    if removed == 0 {
        println!("No git-vulnscan hooks found in the {} git config.", if local { "local" } else { "global" });
    } else {
        println!("Removed {removed} git-vulnscan hook(s).");
    }
    Ok(())
}

/// Where our hooks are configured, e.g. `["global"]`, for `doctor`.
pub fn installed_scopes(dir: &Path) -> Vec<String> {
    // `--show-scope` prefixes each hook with "global\t", "local\t", ...
    let listed = git::try_run(dir, &["hook", "list", "--show-scope", "post-checkout"]).unwrap_or_default();
    listed
        .lines()
        .filter_map(|line| line.split_once('\t'))
        .filter(|(_, name)| *name == HOOKS[0].0)
        .map(|(scope, _)| scope.to_string())
        .collect()
}

/// The binary the installed hooks run, if they're installed.
pub fn installed_binary(dir: &Path) -> Option<String> {
    git::try_run(dir, &["config", "--get", &format!("hook.{}.command", HOOKS[0].0)])
}

fn scope_flag(local: bool) -> &'static str {
    if local { "--local" } else { "--global" }
}

/// The shell command git runs for a hook.
///
/// Git appends the hook's arguments to the command (as `"$@"`), so the
/// result runs like:
///
/// ```sh
/// [ -x '/path/git-vulnscan' ] || { echo >&2 git-vulnscan: ...; exit 0; }; '/path/git-vulnscan' hook post-checkout <args...>
/// ```
///
/// If the binary has been deleted or moved, the guard prints a warning and
/// exits with 0: you notice the scan didn't happen, but git keeps working.
fn hook_command(exe: &Path, event: &str) -> String {
    let quoted = shell_quote(&exe.display().to_string());
    format!(
        "[ -x {quoted} ] || {{ echo >&2 git-vulnscan: warning: no scan, binary missing at {quoted}. \
         Reinstall and run: git vulnscan install-hooks; exit 0; }}; {quoted} hook {event}"
    )
}

/// Quotes a string for `sh`: wrap it in single quotes, and write any single
/// quote inside it as `'\''` (close quote, escaped quote, reopen quote).
fn shell_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', r"'\''"))
}

/// Entry point for `git-vulnscan hook <event> <args...>`, run by git.
///
/// Always returns success: errors are printed as warnings, so a problem with
/// the scanner never breaks your git workflow.
pub fn handle(event: &str, args: &[String]) -> ExitCode {
    let skip = std::env::var_os(SKIP_ENV).is_some_and(|v| !v.is_empty());
    if !skip {
        if let Err(err) = run_hook(event, args) {
            eprintln!("git-vulnscan: warning: {event} hook failed: {err:#}");
        }
    }
    ExitCode::SUCCESS
}

/// What a hook decided to scan, and why (shown to the user).
struct Plan {
    reason: String,
    request: ScanRequest,
}

fn run_hook(event: &str, args: &[String]) -> Result<()> {
    // Git runs hooks from the root of the working tree.
    let repo = git::toplevel(Path::new("."))?;
    let settings = Settings::load(&repo);
    if !settings.enabled {
        return Ok(());
    }

    let plan = match event {
        "post-checkout" => plan_checkout(&repo, &settings, args)?,
        "post-merge" => plan_new_commits(&repo, &settings, "pulled/merged")?,
        // post-rewrite's argument says what rewrote history: "amend" (commit
        // --amend, nothing new to scan) or "rebase".
        "post-rewrite" if args.first().is_some_and(|a| a == "rebase") => {
            plan_new_commits(&repo, &settings, "rebased")?
        }
        _ => None,
    };
    // Nothing worth scanning: stay silent.
    let Some(plan) = plan else {
        return Ok(());
    };

    eprintln!("git-vulnscan: {}, scanning {}...", plan.reason, plan.request.scope());
    let report = scanners::scan(&plan.request, &settings);
    let options = TextOptions {
        color: report::use_color(std::io::stderr().is_terminal()),
        max_per_package: Some(5),
        max_packages: Some(10),
        compact: true,
    };
    // Hooks report on stderr: git shows it, and it doesn't mix with the
    // output of commands that are piped somewhere.
    eprint!("{}", report::render_text(&report, settings.fail_on, &options));
    Ok(())
}

/// Decides what to scan after a checkout.
///
/// `post-checkout` gets three arguments: the previous HEAD, the new HEAD, and
/// a flag that is "1" for a branch checkout or "0" for a file checkout.
fn plan_checkout(repo: &Path, settings: &Settings, args: &[String]) -> Result<Option<Plan>> {
    // A *slice pattern*: matches only if `args` has exactly three elements,
    // and binds each one to a name.
    let [previous, new, branch_flag] = args else {
        return Ok(None);
    };
    if branch_flag != "1" || git::rebase_in_progress(repo) {
        return Ok(None);
    }

    if git::is_null_oid(previous) {
        // No previous HEAD: this is a brand-new checkout.
        if git::is_linked_worktree(repo) {
            // `git worktree add`: the history was scanned when the repository
            // was cloned, but this checkout may be a different branch.
            return Ok(Some(Plan {
                reason: "new worktree".into(),
                request: request(repo, settings, settings.deps, SecretsScope::Off),
            }));
        }
        let secrets = if settings.secrets { SecretsScope::FullHistory } else { SecretsScope::Off };
        return Ok(Some(Plan {
            reason: "fresh clone".into(),
            request: request(repo, settings, settings.deps, secrets),
        }));
    }

    // A branch switch: only rescan if the dependencies differ.
    if previous == new || !settings.deps {
        return Ok(None);
    }
    let changed = git::changed_files(repo, previous, new)?;
    if !depfiles::any_dependency_file(changed.iter().map(String::as_str)) {
        return Ok(None);
    }
    Ok(Some(Plan {
        reason: "dependency files changed".into(),
        request: request(repo, settings, true, SecretsScope::Off),
    }))
}

/// Decides what to scan after a merge, pull or rebase: the commits between
/// `ORIG_HEAD` (where HEAD was before the operation) and the new `HEAD`.
fn plan_new_commits(repo: &Path, settings: &Settings, action: &str) -> Result<Option<Plan>> {
    let (Some(from), Some(to)) = (git::rev_parse(repo, "ORIG_HEAD"), git::rev_parse(repo, "HEAD")) else {
        return Ok(None);
    };
    if from == to {
        return Ok(None);
    }

    let changed = git::changed_files(repo, &from, &to)?;
    let deps = settings.deps && depfiles::any_dependency_file(changed.iter().map(String::as_str));
    let secrets = if settings.secrets { SecretsScope::Range { from, to } } else { SecretsScope::Off };
    if !deps && secrets == SecretsScope::Off {
        return Ok(None);
    }
    Ok(Some(Plan {
        reason: format!("new commits {action}"),
        request: request(repo, settings, deps, secrets),
    }))
}

fn request(repo: &Path, settings: &Settings, deps: bool, secrets: SecretsScope) -> ScanRequest {
    ScanRequest {
        repo: PathBuf::from(repo),
        deps,
        secrets,
        local_db: settings.local_db,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_for_the_shell() {
        assert_eq!(shell_quote("/usr/bin/x"), "'/usr/bin/x'");
        assert_eq!(shell_quote("/it's here"), r"'/it'\''s here'");
    }

    #[test]
    fn hook_command_has_guard() {
        let cmd = hook_command(Path::new("/bin/git-vulnscan"), "post-merge");
        assert!(cmd.starts_with("[ -x '/bin/git-vulnscan' ] || {"));
        // Git appends the arguments, so the actual call must come last.
        assert!(cmd.ends_with("; '/bin/git-vulnscan' hook post-merge"));
    }
}
