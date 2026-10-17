//! git-vulnscan: a git extension that scans the repositories you clone for
//! vulnerable dependencies and leaked secrets.
//!
//! How the pieces fit together:
//!
//! ```text
//!   main.rs      parse the command line, dispatch to a command
//!   cli.rs       command-line definition (clap)
//!   hooks.rs     install/uninstall git hooks; decide what to scan when they fire
//!   scanners/    run osv-scanner and gitleaks in parallel, parse their output
//!   model.rs     Finding, Severity, ScanReport: the common data model
//!   report.rs    render a ScanReport as text or JSON
//!   settings.rs  read `vulnscan.*` settings from git config
//!   git.rs       helpers for running git commands
//!   depfiles.rs  recognise lockfiles/manifests
//!   doctor.rs    `git vulnscan doctor`
//! ```

// Each `mod` line tells the compiler to include a module, from `src/<name>.rs`
// or `src/<name>/mod.rs`. Modules are private by default; items inside them
// are shared with `pub`.
mod cli;
mod depfiles;
mod doctor;
mod git;
mod hooks;
mod model;
mod report;
mod scanners;
mod settings;

use std::io::IsTerminal;
use std::path::PathBuf;
// We already have a `Command` (the CLI enum), so we rename the standard
// library's process `Command` on import to avoid the name clash.
use std::process::{Command as Process, ExitCode};

use anyhow::{Context, Result, bail};
use clap::Parser;

use cli::{CloneArgs, Command, Format, ScanArgs, ScanOptions};
use model::Verdict;
use report::TextOptions;
use scanners::{ScanRequest, SecretsScope};
use settings::Settings;

/// Exit codes, so scripts and CI can react to the result:
/// - 0: nothing at or above the threshold
/// - 1: findings at or above the threshold
/// - 2: error, or a scanner couldn't run
///
/// Returning `ExitCode` from `main` (instead of calling
/// `std::process::exit`) lets destructors run, so temporary files get
/// cleaned up.
fn main() -> ExitCode {
    let cli = cli::Cli::parse();

    // Every command returns `Result<ExitCode>`. `match` on the enum makes the
    // compiler check that every subcommand is handled.
    let result = match cli.command {
        Command::Scan(args) => scan_command(args),
        Command::Clone(args) => clone_command(args),
        Command::InstallHooks(scope) => hooks::install(scope.local).map(|()| ExitCode::SUCCESS),
        Command::UninstallHooks(scope) => hooks::uninstall(scope.local).map(|()| ExitCode::SUCCESS),
        Command::Doctor => doctor::run(),
        Command::Hook { event, args } => Ok(hooks::handle(&event, &args)),
    };

    // One place to print errors. `{:#}` shows the full context chain, e.g.
    // "/tmp/x is not inside a git repository: `git rev-parse` failed: ...".
    result.unwrap_or_else(|err| {
        eprintln!("git-vulnscan: error: {err:#}");
        ExitCode::from(2)
    })
}

/// `git vulnscan scan [PATH]`
fn scan_command(args: ScanArgs) -> Result<ExitCode> {
    let start = args.path.unwrap_or_else(|| PathBuf::from("."));
    let repo = git::toplevel(&start)?;
    let settings = Settings::load(&repo);
    let request = build_request(repo, &settings, &args.options, args.since.as_deref())?;
    scan_and_report(&request, &settings, &args.options)
}

/// `git vulnscan clone <REPOSITORY> [DIRECTORY] [-- GIT_ARGS...]`
fn clone_command(args: CloneArgs) -> Result<ExitCode> {
    let directory = args
        .directory
        .unwrap_or_else(|| PathBuf::from(git::default_clone_dir(&args.repository)));

    let status = Process::new("git")
        .arg("clone")
        .args(&args.git_args)
        // SECURITY: `--` marks the end of options, so a "repository" that
        // starts with a dash (like `--upload-pack=evil`) can't be interpreted
        // as an option by git.
        .arg("--")
        .arg(&args.repository)
        .arg(&directory)
        // We scan below, so the hooks (if installed) shouldn't scan too.
        .env(hooks::SKIP_ENV, "1")
        // `status()` runs the command with our terminal attached, so git's
        // progress output shows up as usual.
        .status()
        .context("failed to run git clone")?;
    if !status.success() {
        bail!("git clone failed ({status})");
    }

    let repo = git::toplevel(&directory)?;
    let settings = Settings::load(&repo);
    let request = build_request(repo, &settings, &args.options, None)?;
    scan_and_report(&request, &settings, &args.options)
}

/// Combines settings and command-line flags into a [`ScanRequest`].
fn build_request(
    repo: PathBuf,
    settings: &Settings,
    options: &ScanOptions,
    since: Option<&str>,
) -> Result<ScanRequest> {
    let deps = settings.deps && !options.no_deps;
    let secrets = if options.no_secrets || !settings.secrets {
        SecretsScope::Off
    } else if let Some(rev) = since {
        let from = git::rev_parse(&repo, rev).with_context(|| format!("unknown revision `{rev}`"))?;
        let to = git::rev_parse(&repo, "HEAD").context("the repository has no commits")?;
        SecretsScope::Range { from, to }
    } else {
        SecretsScope::FullHistory
    };
    if !deps && secrets == SecretsScope::Off {
        bail!("nothing to scan: both the dependency and the secrets scans are turned off");
    }
    Ok(ScanRequest {
        repo,
        deps,
        secrets,
        local_db: options.local_db || settings.local_db,
    })
}

/// Runs the scan, prints the report, and maps the verdict to an exit code.
fn scan_and_report(request: &ScanRequest, settings: &Settings, options: &ScanOptions) -> Result<ExitCode> {
    let fail_on = options.fail_on.unwrap_or(settings.fail_on);

    // Progress goes to stderr so stdout holds only the report (which matters
    // for `--format json > report.json`).
    eprintln!("git-vulnscan: scanning {} ({})...", request.repo.display(), request.scope());
    let report = scanners::scan(request, settings);

    match options.format {
        Format::Text => {
            let text_options = TextOptions {
                color: report::use_color(std::io::stdout().is_terminal()),
                max_per_package: None,
                max_packages: None,
                compact: false,
            };
            print!("{}", report::render_text(&report, fail_on, &text_options));
        }
        Format::Json => println!("{}", report::render_json(&report, fail_on)?),
    }

    Ok(match report.verdict(fail_on) {
        Verdict::Pass => ExitCode::SUCCESS,
        Verdict::Fail => ExitCode::from(1),
        Verdict::Incomplete => ExitCode::from(2),
    })
}
