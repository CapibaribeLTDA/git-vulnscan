//! Command-line interface definition.
//!
//! We use clap's *derive* API: instead of writing a parser by hand, we
//! describe the commands as structs and enums, and `#[derive(Parser)]`
//! generates the parsing code, `--help` text and error messages. The doc
//! comments (`///`) on each item become the help text.
//!
//! Because the binary is named `git-vulnscan`, git finds it on your PATH and
//! lets you type `git vulnscan <command>`; git just runs
//! `git-vulnscan <command>` for you.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::settings::FailOn;

/// Scan git repositories for vulnerable dependencies and leaked secrets.
///
/// Run `git vulnscan install-hooks` once, and every `git clone` and
/// `git pull` will be scanned automatically.
#[derive(Debug, Parser)]
// `version` adds `--version`, using the version from Cargo.toml.
#[command(name = "git-vulnscan", version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

/// The subcommands. Each enum variant becomes one: clap converts the
/// CamelCase names to kebab-case, so `InstallHooks` is `install-hooks`.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Scan a repository (the current one by default).
    Scan(ScanArgs),

    /// Clone a repository with `git clone`, then scan it.
    Clone(CloneArgs),

    /// Make `git clone`, `git pull` and branch switches scan automatically.
    InstallHooks(HookScope),

    /// Remove the hooks added by `install-hooks`.
    UninstallHooks(HookScope),

    /// Check that the scanners and hooks are set up correctly.
    Doctor,

    /// Entry point for the git hooks (not meant to be run by hand).
    #[command(hide = true)]
    Hook {
        /// The git hook event, e.g. "post-checkout".
        event: String,
        /// The arguments git passed to the hook.
        // `allow_hyphen_values` so arguments starting with "-" aren't
        // mistaken for flags.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

/// Options shared by `scan` and `clone`.
///
/// `#[derive(Args)]` makes this a reusable group of arguments; commands
/// include it with `#[command(flatten)]`.
#[derive(Debug, Args)]
pub struct ScanOptions {
    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    pub format: Format,

    /// Exit with status 1 if anything at or above this severity is found
    /// [default: the `vulnscan.failOn` git config, or "high"].
    #[arg(long, value_enum)]
    pub fail_on: Option<FailOn>,

    /// Skip the dependency scan.
    #[arg(long)]
    pub no_deps: bool,

    /// Skip the secrets scan.
    #[arg(long)]
    pub no_secrets: bool,

    /// Match dependencies against a downloaded copy of the OSV database
    /// instead of sending the dependency list to the osv.dev API.
    #[arg(long)]
    pub local_db: bool,
}

#[derive(Debug, Args)]
pub struct ScanArgs {
    /// The repository to scan.
    pub path: Option<PathBuf>,

    /// Only search the commits after REV for secrets (e.g. `--since origin/main`).
    #[arg(long, value_name = "REV")]
    pub since: Option<String>,

    #[command(flatten)]
    pub options: ScanOptions,
}

#[derive(Debug, Args)]
pub struct CloneArgs {
    /// The repository to clone (URL or path).
    pub repository: String,

    /// The folder to clone into [default: derived from the URL, like git does].
    pub directory: Option<PathBuf>,

    #[command(flatten)]
    pub options: ScanOptions,

    /// Extra arguments for `git clone`, after `--`. For example:
    /// `git vulnscan clone <url> -- --depth 1`
    // `last = true` means these come after a literal `--`.
    #[arg(last = true)]
    pub git_args: Vec<String>,
}

#[derive(Debug, Args)]
pub struct HookScope {
    /// Only this repository, instead of the global git config.
    #[arg(long)]
    pub local: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Format {
    Text,
    Json,
}
