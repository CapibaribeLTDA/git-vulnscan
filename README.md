# git-vulnscan

A git extension that scans the repositories you clone for **vulnerable
dependencies**, **known-malicious packages** and **secrets committed to the
history**. Once the hooks are installed, it runs on its own after every
plain `git clone`, so you don't have to remember to check.

```text
$ git clone https://github.com/snyk-labs/nodejs-goof
git-vulnscan: fresh clone, scanning dependencies and full history...

git-vulnscan · ~/code/nodejs-goof (dependencies and full history)
  ✓ dependencies  osv-scanner  266 findings
  ✓ secrets       gitleaks     0 findings

Vulnerable dependencies
  lodash 4.17.4 (npm) · package-lock.json
    CRITICAL  CVE-2019-10744       Prototype Pollution in lodash · upgrade to 4.17.12
    HIGH      CVE-2021-23337       Command Injection in lodash · upgrade to 4.17.21
    …
✗ 36 critical, 116 high, 99 medium, 15 low: at or above the "high" threshold
```

git-vulnscan doesn't detect anything by itself. It runs two established open
source scanners and merges their results:

| Scanner | Finds | Data |
|---|---|---|
| [osv-scanner](https://github.com/google/osv-scanner) (Google) | vulnerable and malicious packages in lockfiles and manifests: npm, PyPI, Cargo, Go, Maven, RubyGems, Composer, NuGet, … and git submodules | [OSV.dev](https://osv.dev), which aggregates the GitHub Advisory Database, PyPA, RustSec, the Go vulnerability database and more, plus OpenSSF's malicious-packages feed |
| [gitleaks](https://github.com/gitleaks/gitleaks) | API keys, tokens, private keys and passwords anywhere in the git history | gitleaks' built-in rules |

## Install

You need:

- a recent **git** with config-based hooks (tested with git 2.56; `git vulnscan doctor` checks this)
- **osv-scanner** and **gitleaks**: `brew install osv-scanner gitleaks`
- **Rust**, to build it: <https://rustup.rs>

```sh
cargo install --path . --root ~/.local   # puts git-vulnscan in ~/.local/bin
git vulnscan install-hooks               # turns on automatic scanning
git vulnscan doctor                      # checks everything is in place
```

Any executable named `git-<name>` on your PATH becomes `git <name>`. That's
how `git vulnscan` works.

## Automatic scanning

Git won't let an alias replace a built-in command like `clone`. Instead,
`install-hooks` adds config-based hooks (`hook.<name>.command`) to your
global `~/.gitconfig`. They apply to every repository, including ones you
cloned before installing, and run *alongside* each repo's own hooks
instead of replacing them.

| You run | git-vulnscan scans |
|---|---|
| `git clone` | all dependencies + the full history for secrets |
| `git pull` / `git merge` | the new commits for secrets, + dependencies if a lockfile changed |
| `git pull --rebase` / `git rebase` | same as pull |
| `git switch` / `git checkout <branch>` | dependencies, only if they differ between the branches |
| `git worktree add` | dependencies |

Hooks never fail the git command, since the clone has already happened by
then. They report on the terminal instead.

- Skip once: `GIT_VULNSCAN_SKIP=1 git clone …`
- Turn off for one repository: `git config vulnscan.enabled false`
- Remove the hooks: `git vulnscan uninstall-hooks`

## Manual commands

```sh
git vulnscan scan                       # scan the current repository
git vulnscan scan path/to/repo --format json > report.json
git vulnscan scan --since origin/main   # only search new commits for secrets
git vulnscan clone <url> [dir] [-- --depth 1]   # clone, then scan (useful without hooks)
git vulnscan doctor
```

Options for `scan` and `clone`: `--fail-on <critical|high|medium|low|any|never>`,
`--no-deps`, `--no-secrets`, `--local-db`, `--format <text|json>`.

Exit codes: **0** nothing at or above the threshold, **1** findings at or
above the threshold, **2** error, or a scanner couldn't run (so the
repository can't be vouched for).

## Settings

Settings live in git config, so you can set global defaults and override them
per repository (`git config` without `--global`).

| Setting | Default | Meaning |
|---|---|---|
| `vulnscan.enabled` | `true` | turn the hooks on or off |
| `vulnscan.failOn` | `high` | the threshold for exit code 1 |
| `vulnscan.deps` | `true` | run the dependency scan |
| `vulnscan.secrets` | `true` | run the secrets scan (turn off if huge histories make clones slow) |
| `vulnscan.localDb` | `false` | match against a downloaded OSV database (see Privacy) |
| `vulnscan.osvScanner` | found on PATH | path to the osv-scanner binary |
| `vulnscan.gitleaks` | found on PATH | path to the gitleaks binary |

Example: `git config --global vulnscan.failOn critical`

### Allowlists

To silence false positives or accepted risks, put these files in
`~/.config/git-vulnscan/`:

- `osv-scanner.toml`: an [osv-scanner config](https://google.github.io/osv-scanner/configuration/), e.g. `[[IgnoredVulns]]`
- `gitleaks.toml`: a [gitleaks config](https://github.com/gitleaks/gitleaks#configuration) (start it with `[extend]` / `useDefault = true`)
- `.gitleaksignore`: one finding fingerprint per line (fingerprints are in the `--format json` output)

## Security design

The repositories being scanned are untrusted, so a few decisions matter:

- **Repositories can't silence the scanners.** Both scanners read settings
  from the folder they scan (`osv-scanner.toml`, `.gitleaks.toml`,
  `.gitleaksignore`, inline `gitleaks:allow` comments), and a malicious repo
  could ship them to hide its own findings. git-vulnscan always passes its own
  config and ignore paths, and disables `gitleaks:allow`.
- **Tracked files can't hide behind `.gitignore`.** osv-scanner skips
  gitignored files by default. A repo could commit a lockfile and also list it
  in `.gitignore`, so git-vulnscan uses `--no-ignore`.
- **No repository code is executed.** Lockfiles are parsed statically. Nothing
  runs `npm install`, build scripts or the repo's own hooks (git never clones
  hooks).
- **Secrets are redacted** from all output (`gitleaks --redact`).
- `git vulnscan clone` passes `--` before the URL, so a "URL" like
  `--upload-pack=…` can't be read as an option by git.

There are end-to-end tests for each of these in `tests/cli.rs`.

## Privacy

By default osv-scanner sends the **names and versions** of your dependencies
to the osv.dev API (run by Google). No code or file contents are sent. If
that's a concern, set `vulnscan.localDb true` (or pass `--local-db`).
osv-scanner then downloads the vulnerability database for the ecosystems in
use and matches locally. The first run in each ecosystem is slower while the
database downloads.

## Known gaps

- `git clone --no-checkout` doesn't trigger a hook, so it isn't scanned.
- Repositories that were already cloned are scanned on their next pull. Run
  `git vulnscan scan` to check one right away.
- Dependency results are only as complete as the lockfiles. A project with
  just a `requirements.txt` of unpinned ranges, or no lockfile at all, can't
  be fully resolved without running the package manager, which this tool
  deliberately never does.
- Findings aren't checked for reachability. A vulnerable function may never
  be called by the project.

## Learning Rust with this code

The code is commented for readers new to Rust. Suggested reading order:

1. **`src/model.rs`**: enums with data, deriving traits (`Ord` ordering by
   declaration, `Serialize`), `Option`, `match`, mutable references.
2. **`src/settings.rs`**: `Default`, string parsing, `Option` combinators
   (`map`, `filter`, `or_else`), the `?` operator on `Option`.
3. **`src/git.rs`**: running processes, `Result` and `?`, error context with
   `anyhow`, `let … else`.
4. **`src/scanners/osv.rs`**: deserializing JSON with serde attributes,
   iterator chains, `BTreeSet`, temporary files and RAII cleanup.
5. **`src/scanners/mod.rs`**: scoped threads borrowing data, generic
   functions taking closures (`FnOnce`), `#[cfg(unix)]`, UTF-8-safe slicing.
6. **`src/report.rs`**: lifetimes on functions that return borrowed data,
   building strings, `#[serde(flatten)]`.
7. **`src/hooks.rs`**: slice patterns (`let [a, b, c] = args else …`), shell
   quoting, how git hooks work.
8. **`src/main.rs`** and **`src/cli.rs`**: clap's derive API, `ExitCode`.
9. **`tests/cli.rs`**: integration tests that drive the real binary, with
   fake programs standing in for external tools.

## Development

```sh
cargo test                   # unit tests + end-to-end tests (no network needed)
cargo clippy --all-targets   # lints
cargo build --release
```

Ideas for next steps: SARIF output for code-scanning dashboards; ranking by
[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and
[EPSS](https://www.first.org/epss/) so actually-exploited issues come first; a
code scan with [Opengrep](https://github.com/opengrep/opengrep); a `pre-push`
hook that blocks pushing new secrets.
