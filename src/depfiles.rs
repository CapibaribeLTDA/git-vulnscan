//! Recognising dependency files (lockfiles and manifests).
//!
//! The hooks use this to decide whether a `git pull` or branch switch changed
//! the project's dependencies. If it didn't, there's no point re-running the
//! dependency scan. osv-scanner itself knows how to *parse* all of these.

/// File names that list dependencies, matched exactly.
///
/// A `const` slice of string literals is baked into the binary; nothing is
/// allocated at runtime.
const EXACT_NAMES: &[&str] = &[
    // JavaScript / TypeScript
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lock",
    "deno.lock",
    // Python
    "Pipfile.lock",
    "poetry.lock",
    "uv.lock",
    "pdm.lock",
    "pylock.toml",
    "pyproject.toml",
    // Rust
    "Cargo.lock",
    // Go
    "go.mod",
    // Ruby
    "Gemfile.lock",
    "gems.locked",
    // PHP
    "composer.lock",
    // Java / Kotlin
    "pom.xml",
    "gradle.lockfile",
    "buildscript-gradle.lockfile",
    "verification-metadata.xml",
    // .NET
    "packages.lock.json",
    "packages.config",
    // Others
    "mix.lock",
    "pubspec.lock",
    "renv.lock",
    "conan.lock",
    "Package.resolved",
    "Podfile.lock",
    "cabal.project.freeze",
    "stack.yaml.lock",
    // Submodules are dependencies too: osv-scanner checks their commits.
    ".gitmodules",
];

/// True if `path` (as printed by `git diff --name-only`) is a dependency file.
pub fn is_dependency_file(path: &str) -> bool {
    // Git always uses `/` as the separator, on every platform. `rsplit` walks
    // from the end, so `.next()` is the last component: the file name.
    let name = path.rsplit('/').next().unwrap_or(path);

    EXACT_NAMES.contains(&name)
        // requirements.txt, requirements-dev.txt, requirements/prod.txt...
        || (name.starts_with("requirements") && name.ends_with(".txt"))
        || (path.contains("requirements/") && name.ends_with(".txt"))
        || name.ends_with(".deps.json")
        || path.ends_with("vendor/modules.txt")
}

/// True if any of `paths` is a dependency file.
///
/// `impl IntoIterator<Item = &'a str>` accepts anything we can loop over that
/// yields string slices: a Vec, an array, an iterator... The `'a` is a
/// lifetime parameter, which tells the compiler the slices are borrowed from
/// somewhere that outlives this call.
pub fn any_dependency_file<'a>(paths: impl IntoIterator<Item = &'a str>) -> bool {
    paths.into_iter().any(is_dependency_file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_lockfiles() {
        assert!(is_dependency_file("package-lock.json"));
        assert!(is_dependency_file("services/api/Cargo.lock"));
        assert!(is_dependency_file("requirements-dev.txt"));
        assert!(is_dependency_file("requirements/prod.txt"));
        assert!(is_dependency_file("src/App.deps.json"));
        assert!(is_dependency_file("vendor/modules.txt"));
    }

    #[test]
    fn ignores_other_files() {
        assert!(!is_dependency_file("README.md"));
        assert!(!is_dependency_file("src/main.rs"));
        assert!(!is_dependency_file("docs/requirements.md"));
        assert!(!any_dependency_file(["a.txt", "b/c.rs"]));
    }
}
