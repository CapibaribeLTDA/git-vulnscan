//! `git vulnscan doctor`: checks the setup and explains what's missing.

use std::process::ExitCode;

use anyhow::Result;

use crate::hooks;
use crate::scanners::{GITLEAKS, OSV_SCANNER, Tool};
use crate::settings::{self, Settings};

pub fn run() -> Result<ExitCode> {
    let cwd = std::env::current_dir()?;
    let settings = Settings::load(&cwd);
    // `mut` because we flip it to false as problems are found.
    let mut healthy = true;

    println!("git-vulnscan {}", env!("CARGO_PKG_VERSION"));

    // Pairs of (tool, path configured in git config). `as_deref` turns
    // `&Option<PathBuf>` into `Option<&Path>`.
    let tools: [(&Tool, Option<&std::path::Path>); 2] = [
        (&OSV_SCANNER, settings.osv_scanner.as_deref()),
        (&GITLEAKS, settings.gitleaks.as_deref()),
    ];
    for (tool, configured) in tools {
        match tool.locate(configured) {
            Some(path) => {
                let version = tool.version(&path).unwrap_or_else(|| "unknown version".into());
                println!("  ✓ {:<12} {version} at {}", tool.name, path.display());
            }
            None => {
                healthy = false;
                println!("  ✗ {:<12} not found. Install it: {}", tool.name, tool.install_hint);
            }
        }
    }

    let scopes = hooks::installed_scopes(&cwd);
    if scopes.is_empty() {
        healthy = false;
        println!("  ✗ {:<12} not installed. Run: git vulnscan install-hooks", "hooks");
    } else {
        let events: Vec<&str> = hooks::HOOKS.iter().map(|(_, event)| *event).collect();
        println!("  ✓ {:<12} installed ({}) for {}", "hooks", scopes.join(", "), events.join(", "));

        // Warn if the hooks run a different binary than this one, e.g. after
        // reinstalling git-vulnscan somewhere else.
        let exe = std::env::current_exe().ok().and_then(|p| p.canonicalize().ok());
        if let (Some(command), Some(exe)) = (hooks::installed_binary(&cwd), exe) {
            if !command.contains(&exe.display().to_string()) {
                healthy = false;
                println!("    ! the hooks run a different binary: {command}");
                println!("      Run `git vulnscan install-hooks` again to point them here.");
            }
        }
    }
    if !settings.enabled {
        println!("  ! {:<12} vulnscan.enabled is false here: hooks won't scan", "disabled");
    }

    match settings::config_dir() {
        Some(dir) => {
            let present: Vec<&str> = ["osv-scanner.toml", "gitleaks.toml", ".gitleaksignore"]
                .into_iter()
                .filter(|name| dir.join(name).is_file())
                .collect();
            let detail = if present.is_empty() { "none yet".to_string() } else { present.join(", ") };
            println!("  · {:<12} {} ({detail})", "allowlists", dir.display());
        }
        None => println!("  · {:<12} no home folder found", "allowlists"),
    }
    println!(
        "  · {:<12} fail on {}, deps {}, secrets {}, local db {}",
        "settings",
        settings.fail_on.name(),
        on_off(settings.deps),
        on_off(settings.secrets),
        on_off(settings.local_db),
    );

    Ok(if healthy { ExitCode::SUCCESS } else { ExitCode::FAILURE })
}

fn on_off(value: bool) -> &'static str {
    if value { "on" } else { "off" }
}
