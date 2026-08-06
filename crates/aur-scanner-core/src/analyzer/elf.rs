//! Embedded-ELF trojan detection over the already-cloned source tree.
//!
//! Wave-3 (Aug 2026) Atomic Arch packages embed a *compiled ELF binary* into
//! the AUR git repo under a benign tool name (linter, minifier, parser,
//! assembler, translator, optimizer) and execute it from `build()`/`package()`.
//! ATOMIC-011 (a text rule in `rules/mod.rs`) already flags the execution line;
//! this analyzer supplies the *confirming* half: that the file on disk really is
//! a compiled ELF and not, say, a shell wrapper or an empty placeholder.
//!
//! Because the `check`/`scan` commands clone the whole AUR repo into a temp dir
//! before scanning, the full source tree is already on disk at `file_path`
//! (the PKGBUILD lives at `<temp_dir>/PKGBUILD`). We walk that tree — no extra
//! download — looking for ELF magic under the disguise names.
//!
//! Safety: read-only, never executes anything, only reads the first 4 bytes for
//! magic (cheap regardless of file size), skips `.git`, and refuses to follow
//! symlinks so a hostile symlink cannot point the walk outside the clone.

use super::SecurityAnalyzer;
use crate::error::Result;
use crate::types::{AnalysisContext, Category, Finding, Location, Severity};
use async_trait::async_trait;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// The ELF magic bytes: `\x7fELF`.
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

/// Benign tool names that Wave-3 embedded-ELF trojans disguise under. Must stay
/// in lockstep with ATOMIC-011's regex so the text rule and this binary
/// confirmation agree on what a "disguised helper" is.
const DISGUISE_NAMES: &[&str] = &[
    "linter",
    "minifier",
    "parser",
    "assembler",
    "translator",
    "optimizer",
];

/// Function names in a PKGBUILD whose bodies we check for execution of a
/// disguised helper (makepkg runs these during a build).
const BUILD_FUNCTIONS: &[&str] = &["build", "package"];

/// Detect whether the file at `path` starts with the ELF magic bytes.
///
/// Read-only and cheap: only the first 4 bytes are read, so file size does not
/// matter (we never pull a hostile multi-GB file into memory). This function
/// does **not** guard against symlinks itself — `File::open` follows a link, so
/// callers MUST pass only non-symlink paths (the walker filters them first).
pub fn is_elf(path: &Path) -> bool {
    use std::io::Read;
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    let mut buf = [0u8; 4];
    // A short file (or a read error) is simply not an ELF.
    if f.read_exact(&mut buf).is_err() {
        return false;
    }
    buf == ELF_MAGIC
}

/// The set of basenames we consider "disguised helpers".
pub fn disguise_name_set() -> HashSet<String> {
    DISGUISE_NAMES.iter().map(|s| s.to_string()).collect()
}

/// Directory basenames that are never source code a build() would execute an
/// embedded helper from, but can be enormous (vendored deps, build artifacts,
/// VCS internals). Traversing them is a DoS vector on a hostile repo and pure
/// waste on a legit one, so the walk skips them entirely.
const SKIP_DIRS: &[&str] = &[
    ".git", ".hg", ".svn", ".cargo", "node_modules", "target", "dist", "build",
    "vendor", ".gradle", "out",
];

/// Hard cap on how many directory entries the walk will visit. Bounds the CPU
/// and syscall cost of scanning a hostile repo that ships millions of tiny
/// files (a self-inflicted DoS otherwise). The disguise-name list is tiny, so
/// a legitimate AUR package never needs anywhere near this budget.
const MAX_WALK_ENTRIES: usize = 200_000;

/// Hard cap on how many disguise-named candidates we will actually `open()`
/// (read the ELF magic of). An adversarial repo could plant many such files;
/// we bound the file-open work so one package cannot stall a bulk scan.
const MAX_ELF_CANDIDATES: usize = 512;

/// Recursively walk `root`, yielding regular-file paths whose basename is one
/// of the disguise names. `.git` (and other heavy/non-source dirs) are
/// skipped; symlinks are not followed (a symlink is reported as neither a dir
/// to descend into nor a file to check), so the walk can never escape `root`
/// through a hostile link. The walk is bounded by [`MAX_WALK_ENTRIES`] and
/// yields at most [`MAX_ELF_CANDIDATES`] candidates, so a pathological tree
/// cannot stall a scan.
pub fn walk_source_tree(root: &Path, names: &HashSet<String>) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    let mut visited = 0usize;
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            if visited >= MAX_WALK_ENTRIES {
                tracing::warn!(
                    "elf walk aborted at {} entries (budget {}); tree may be incomplete",
                    visited,
                    MAX_WALK_ENTRIES
                );
                return found;
            }
            visited += 1;
            // Log transient I/O failures instead of silently swallowing them:
            // for a security scanner a silent continue can hide a detection.
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(e) => {
                    tracing::debug!(
                        "elf walk: metadata failed for {}: {}",
                        entry.path().display(),
                        e
                    );
                    continue;
                }
            };
            let path = entry.path();
            let fname = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) => n,
                None => continue,
            };
            if meta.is_dir() {
                // Never descend into .git or other heavy/non-source dirs (repo
                // internals are not part of the source tree the build sees) and
                // never follow symlinked dirs.
                if !SKIP_DIRS.contains(&fname) {
                    stack.push(path);
                }
            } else if meta.is_file() {
                if names.contains(fname) {
                    found.push(path);
                    if found.len() >= MAX_ELF_CANDIDATES {
                        return found;
                    }
                }
            }
            // Symlinks and other special files are ignored entirely.
        }
    }
    found
}

/// Whether any `build()`/`package()` body executes the given basename as a
/// command. Mirrors ATOMIC-011's correlation: the text rule already confirms
/// execution; this tells the finding which function(s) run it.
///
/// Handles `$srcdir/name`, `${srcdir}/name`, bare `name`, `./name`,
/// `"$srcdir/name"`, `"./name"`, and command position after `; | & && (`
/// / newline. Matches the whole token so `linter-helpers` or `optimizer.c`
/// never count as execution of `linter`/`optimizer`.
fn executed_in_build(pkgbuild: &crate::parser::ParsedPkgbuild, name: &str) -> bool {
    use regex::Regex;
    // Command-word position: start of line, after `; | & && (`, or after a
    // `then`/`do`/`else` keyword (the same separator set ATOMIC-011 uses). The
    // token is an optional opening quote, an optional `$srcdir/`/`${srcdir}/`/
    // `./` prefix, the exact escaped name, an optional closing quote, then a
    // *mandatory* delimiter (whitespace, `/`, `;`, `&`, `|`, `(`, `)`, or end
    // of line). The delimiter is NOT optional and there is NO `\b`: that is
    // what stops `linter-helpers`, `optimizer.c`, `linter=1` from matching
    // (`-`, `.`, `=` are not delimiters) while still allowing `linter --go`
    // and `linter"`.
    let sep = r"(?:^\s*|[;&|(]\s*|&&\s*|;&&\s*|\bthen\s*|\bdo\s*|\belse\s*)";
    let re = Regex::new(&format!(
        r#"{sep}["']?(?:\$\{{?srcdir\}}?/|\./)?{}["']?(?:[\s/;&|()]|$)"#,
        regex::escape(name)
    ))
    .expect("statically-valid embedded-ELF execution regex");

    for fn_name in BUILD_FUNCTIONS {
        if let Some(body) = pkgbuild.functions.get(*fn_name) {
            if body.content.lines().any(|l| re.is_match(l)) {
                return true;
            }
        }
    }
    false
}

/// Whether any `build()`/`package()` body makes the given basename executable
/// via `chmod +x` (the Wave-3 preparation step that makes an embedded ELF run).
/// Mirrors ATOMIC-011's `chmod` pattern so the two stay in lockstep.
fn chmod_in_build(pkgbuild: &crate::parser::ParsedPkgbuild, name: &str) -> bool {
    use regex::Regex;
    // `chmod` (with optional flags/mode) on a $srcdir/./bare disguise-named
    // file, at command position. Same delimiter discipline as executed_in_build.
    let sep = r"(?:^\s*|[;&|(]\s*|&&\s*|;&&\s*|\bthen\s*|\bdo\s*|\belse\s*)";
    let re = Regex::new(&format!(
        r#"{sep}chmod\s+(?:-[A-Za-z]+\s+)*[ugoa]*\+x\s+["']?(?:\$\{{?srcdir\}}?/|\./)?{}["']?(?:[\s/;&|()]|$)"#,
        regex::escape(name)
    ))
    .expect("statically-valid embedded-ELF chmod regex");

    for fn_name in BUILD_FUNCTIONS {
        if let Some(body) = pkgbuild.functions.get(*fn_name) {
            if body.content.lines().any(|l| re.is_match(l)) {
                return true;
            }
        }
    }
    false
}

/// Analyzer that scans the already-cloned source tree for compiled ELF
/// binaries disguised under benign tool names (Wave-3 embedded-ELF trojan).
pub struct ElfAnalyzer;

impl ElfAnalyzer {
    /// Create a new embedded-ELF analyzer.
    pub fn new() -> Self {
        Self
    }

    /// Run the ELF walk over the source tree rooted at `dir` and emit ATOMIC-012
    /// findings for any disguised file that is genuinely a compiled ELF.
    pub fn analyze_tree(
        &self,
        dir: &Path,
        pkgbuild: &crate::parser::ParsedPkgbuild,
    ) -> Vec<Finding> {
        let names = disguise_name_set();
        let mut findings = Vec::new();
        for path in walk_source_tree(dir, &names) {
            if !is_elf(&path) {
                continue;
            }
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("?")
                .to_string();
            // Correlation: is this disguised ELF actually run (or made
            // executable) from a build()/package() body? Only a confirmed
            // execution/chmod is a full embedded-ELF trojan; a compiled ELF
            // merely *present* under one of the six generic names (which are
            // also real product-binary names for legit projects) is a strong
            // but not conclusive signal.
            let executed = executed_in_build(pkgbuild, &name);
            let chmodded = chmod_in_build(pkgbuild, &name);
            let correlated = executed || chmodded;
            // Relativize the path so the report (and Location.file) never leaks
            // the absolute temp/clone layout.
            let rel = path
                .strip_prefix(dir)
                .unwrap_or(&path)
                .to_string_lossy()
                .to_string();
            let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            let mut title = format!(
                "Compiled ELF binary disguised as a source tool ({name})"
            );
            if executed {
                title.push_str(", executed in build()/package()");
            } else if chmodded {
                title.push_str(", made executable in build()/package()");
            }
            findings.push(Finding {
                id: "ATOMIC-012".to_string(),
                // Critical only when the file is actually run or made executable
                // in a build function; otherwise High (suspicious presence).
                severity: if correlated {
                    Severity::Critical
                } else {
                    Severity::High
                },
                category: Category::MaliciousCode,
                title,
                description: format!(
                    "The source tree contains a compiled ELF binary at `{rel}` named `{name}` — \
                     one of the benign tool names Wave-3 (Aug 2026) Atomic Arch packages use to \
                     smuggle a stage-1 loader into build(). {}\
                     ATOMIC-011 confirms the execution line; ATOMIC-012 confirms the file is \
                     genuinely a compiled binary, not a script or placeholder.",
                    if correlated {
                        "It is executed (or made executable) from a build()/package() function. "
                    } else {
                        "It is not directly invoked or made executable in the parsed \
                         build()/package() text. A compiled ELF under a generic tool name could \
                         be a legitimate product binary, so this is elevated (not Critical) pending \
                         manual review. "
                    }
                ),
                location: Location {
                    file: PathBuf::from(&rel),
                    line: None,
                    column: None,
                    snippet: None,
                },
                recommendation:
                    "Do NOT build. A compiled ELF hidden under a benign tool name in the source \
                     tree is an embedded-ELF trojan vector. Inspect the PKGBUILD diff, report the \
                     package, and treat the host as potentially compromised (check for stage-2 \
                     artifacts per ATOMIC-006/007)."
                        .to_string(),
                cwe_id: Some("CWE-506".to_string()),
                metadata: serde_json::json!({
                    "elf": true,
                    "file": rel,
                    "name": name,
                    "size_bytes": size,
                    "executed_in_build": executed,
                    "chmod_in_build": chmodded,
                    "correlated": correlated,
                    "functions": BUILD_FUNCTIONS,
                }),
            });
        }
        findings
    }
}

#[async_trait]
impl SecurityAnalyzer for ElfAnalyzer {
    async fn analyze(&self, context: &AnalysisContext) -> Result<Vec<Finding>> {
        // The PKGBUILD's parent directory is the cloned source-tree root
        // (temp_dir for a network fetch, or the user-supplied --local dir).
        let dir = context
            .file_path
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_default();
        Ok(self.analyze_tree(&dir, &context.pkgbuild))
    }

    fn name(&self) -> &str {
        "elf"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- ELF magic detection ------------------------------------------------

    #[test]
    fn elf_magic_detects_real_elf_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("sample");
        std::fs::write(&p, [0x7f, b'E', b'L', b'F', 2, 1, 1, 0]).unwrap();
        assert!(is_elf(&p), "\\x7fELF prefix must be detected");
    }

    #[test]
    fn elf_magic_rejects_non_elf() {
        let dir = tempfile::tempdir().unwrap();
        // Plain text file.
        let text = dir.path().join("x.txt");
        std::fs::write(&text, "hello world\n").unwrap();
        assert!(!is_elf(&text));

        // Empty file.
        let empty = dir.path().join("empty");
        std::fs::write(&empty, []).unwrap();
        assert!(!is_elf(&empty));

        // Short file (only 2 bytes).
        let short = dir.path().join("short");
        std::fs::write(&short, [0x7f, b'E']).unwrap();
        assert!(!is_elf(&short));

        // Shell script.
        let script = dir.path().join("optimizer");
        std::fs::write(&script, "#!/bin/sh\necho hi\n").unwrap();
        assert!(!is_elf(&script));
    }

    #[test]
    fn elf_magic_missing_file_is_not_elf() {
        assert!(!is_elf(Path::new("/nonexistent/definitely/not/here")));
    }

    // --- source-tree walk ---------------------------------------------------

    #[test]
    fn walk_finds_disguise_names_and_skips_git_and_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("src").join("deep")).unwrap();
        std::fs::write(root.join("src").join("linter"), "x").unwrap();
        std::fs::write(root.join("src").join("deep").join("optimizer"), "x").unwrap();
        // .git must be skipped entirely.
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::write(root.join(".git").join("optimizer"), "x").unwrap();
        // A symlink named like a disguise name must NOT be followed.
        #[cfg(unix)]
        std::os::unix::fs::symlink("/etc/passwd", root.join("src").join("parser")).unwrap();
        // A regular file with a non-disguise name must not match.
        std::fs::write(root.join("src").join("build.sh"), "x").unwrap();

        let names = disguise_name_set();
        let found = walk_source_tree(root, &names);
        let mut names_found: Vec<String> = found
            .iter()
            .map(|p| p.file_name().unwrap().to_str().unwrap().to_string())
            .collect();
        names_found.sort();
        assert_eq!(names_found, vec!["linter".to_string(), "optimizer".to_string()]);
    }

    // --- ATOMIC-012 finding emission ----------------------------------------

    #[test]
    fn elf_binary_under_disguise_name_fires_atomic012() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // A genuine compiled ELF named "linter" (the disguise). No build()
        // function executes it, so this is a *suspicious presence* finding.
        std::fs::write(
            root.join("linter"),
            [0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0],
        )
        .unwrap();
        let pkgbuild = crate::parser::ParsedPkgbuild::default();
        let analyzer = ElfAnalyzer::new();
        let findings = analyzer.analyze_tree(root, &pkgbuild);
        assert!(
            findings.iter().any(|f| f.id == "ATOMIC-012"),
            "expected ATOMIC-012 for an ELF named 'linter'; got {:?}",
            findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
        assert_eq!(
            findings[0].cwe_id.as_deref(),
            Some("CWE-506"),
            "ATOMIC-012 must carry CWE-506"
        );
    }

    #[test]
    fn elf_present_but_not_executed_is_high_not_critical() {
        // Dual-LLM HIGH-2 fix: a compiled ELF merely *present* under a generic
        // name (no build()/package() execution or chmod correlation) is High,
        // NOT Critical — it could be a legit product binary.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(
            root.join("optimizer"),
            [0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0],
        )
        .unwrap();
        // build() that never runs or chmods "optimizer".
        let pkgbuild = pkgbuild_with_build("make && make install");
        let analyzer = ElfAnalyzer::new();
        let findings = analyzer.analyze_tree(root, &pkgbuild);
        let f = findings
            .iter()
            .find(|f| f.id == "ATOMIC-012")
            .expect("ATOMIC-012 should fire");
        assert_eq!(
            f.severity,
            Severity::High,
            "unexecuted ELF under generic name must be High, not Critical"
        );
        assert_eq!(
            f.metadata["correlated"], false,
            "correlation flag must be false"
        );
    }

    #[test]
    fn elf_executed_in_build_is_critical() {
        // The real trojan case: the disguised ELF is executed from build().
        // Only this (or a chmod +x) elevates to Critical.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(
            root.join("optimizer"),
            [0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0],
        )
        .unwrap();
        let pkgbuild = pkgbuild_with_build("  \"$srcdir/optimizer\"");
        let analyzer = ElfAnalyzer::new();
        let findings = analyzer.analyze_tree(root, &pkgbuild);
        let f = findings
            .iter()
            .find(|f| f.id == "ATOMIC-012")
            .expect("ATOMIC-012 should fire");
        assert_eq!(
            f.severity,
            Severity::Critical,
            "ELF executed in build() must be Critical"
        );
        assert_eq!(f.metadata["executed_in_build"], true);
    }

    #[test]
    fn elf_chmodded_in_build_is_critical() {
        // The Wave-3 preparation step (chmod +x) also elevates to Critical.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(
            root.join("linter"),
            [0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0],
        )
        .unwrap();
        let pkgbuild = pkgbuild_with_build("    chmod +x \"$srcdir/linter\"");
        let analyzer = ElfAnalyzer::new();
        let findings = analyzer.analyze_tree(root, &pkgbuild);
        let f = findings
            .iter()
            .find(|f| f.id == "ATOMIC-012")
            .expect("ATOMIC-012 should fire");
        assert_eq!(
            f.severity,
            Severity::Critical,
            "ELF made executable (chmod +x) in build() must be Critical"
        );
        assert_eq!(f.metadata["chmod_in_build"], true);
    }

    #[test]
    fn legit_project_shipping_compiled_optimizer_binary_is_not_critical() {
        // Dual-LLM HIGH-2 FP regression: a legitimate project that ships a
        // product binary literally named "optimizer" (installed, not executed
        // in build) must NOT be Critical. ATOMIC-011's `install`/`cp` exclusions
        // already keep it off the Critical path there; ATOMIC-012 must agree.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(
            root.join("optimizer"),
            [0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0],
        )
        .unwrap();
        // build() only installs it into $pkgdir — never executes or chmods it.
        let pkgbuild = pkgbuild_with_build(
            "install -Dm755 \"$srcdir/optimizer\" \"$pkgdir/usr/bin/optimizer\"",
        );
        let analyzer = ElfAnalyzer::new();
        let findings = analyzer.analyze_tree(root, &pkgbuild);
        let f = findings
            .iter()
            .find(|f| f.id == "ATOMIC-012")
            .expect("ATOMIC-012 should fire (High)");
        assert!(
            f.severity != Severity::Critical,
            "legit shipped 'optimizer' binary must NOT be Critical; got {:?}",
            f.severity
        );
        assert_eq!(f.severity, Severity::High);
    }

    #[test]
    fn walk_skips_heavy_dirs_and_is_bounded() {
        // node_modules/target/vendor etc. must not be traversed (DoS guard).
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("node_modules").join("pkg")).unwrap();
        std::fs::write(root.join("node_modules").join("pkg").join("optimizer"), "x").unwrap();
        std::fs::create_dir_all(root.join("target").join("debug")).unwrap();
        std::fs::write(root.join("target").join("debug").join("parser"), "x").unwrap();
        std::fs::create_dir_all(root.join("vendor")).unwrap();
        std::fs::write(root.join("vendor").join("minifier"), "x").unwrap();
        // A real disguise-name ELF at the root must still be found.
        std::fs::write(root.join("linter"), "x").unwrap();

        let names = disguise_name_set();
        let found = walk_source_tree(root, &names);
        let names_found: Vec<String> = found
            .iter()
            .map(|p| p.file_name().unwrap().to_str().unwrap().to_string())
            .collect();
        assert_eq!(
            names_found,
            vec!["linter".to_string()],
            "heavy dirs must be skipped; found {:?}",
            names_found
        );
    }

    #[test]
    fn shell_script_under_disguise_name_does_not_fire_atomic012() {
        // A shell script named "optimizer" is NOT an ELF -> no ATOMIC-012. This
        // is the FP guard: the name alone must not be enough; it must be a real
        // compiled binary. (A legit build could ship a `parser` script that
        // makepkg invokes.)
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("optimizer"), "#!/bin/sh\necho run\n").unwrap();
        let pkgbuild = crate::parser::ParsedPkgbuild::default();
        let analyzer = ElfAnalyzer::new();
        let findings = analyzer.analyze_tree(root, &pkgbuild);
        assert!(
            findings.iter().all(|f| f.id != "ATOMIC-012"),
            "shell script must not fire ATOMIC-012; got {:?}",
            findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn elf_named_like_a_legit_tool_does_not_fire_atomic012() {
        // A real compiled ELF named "configure" or "make" or "gcc" is normal in
        // a build tree and must NOT fire — only the disguise names do.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        for legit in ["configure", "make", "gcc", "cc", "build.sh"] {
            std::fs::write(root.join(legit), [0x7f, b'E', b'L', b'F', 2, 1, 1, 0]).unwrap();
        }
        let pkgbuild = crate::parser::ParsedPkgbuild::default();
        let analyzer = ElfAnalyzer::new();
        let findings = analyzer.analyze_tree(root, &pkgbuild);
        assert!(
            findings.is_empty(),
            "ELF under a legit tool name must not fire ATOMIC-012; got {:?}",
            findings
        );
    }

    // --- executed_in_build correlation ---------------------------------------

    fn pkgbuild_with_build(body: &str) -> crate::parser::ParsedPkgbuild {
        let mut functions = std::collections::HashMap::new();
        functions.insert(
            "build".to_string(),
            crate::parser::FunctionBody {
                name: "build".to_string(),
                content: body.to_string(),
                line_start: 1,
                line_end: 10,
            },
        );
        crate::parser::ParsedPkgbuild {
            functions,
            ..Default::default()
        }
    }

    #[test]
    fn executed_in_build_detects_direct_and_srcdir_invocation() {
        assert!(executed_in_build(&pkgbuild_with_build("  \"$srcdir/linter\""), "linter"));
        assert!(executed_in_build(&pkgbuild_with_build("$srcdir/optimizer --go"), "optimizer"));
        assert!(executed_in_build(&pkgbuild_with_build("make && \"./parser\""), "parser"));
        assert!(executed_in_build(&pkgbuild_with_build("cd \"$srcdir\" && ./assembler"), "assembler"));
        assert!(executed_in_build(&pkgbuild_with_build("\"$srcdir/translator\" --in x"), "translator"));
        assert!(executed_in_build(&pkgbuild_with_build("    \"${srcdir}/minifier\""), "minifier"));
    }

    #[test]
    fn executed_in_build_matches_then_do_else_separators() {
        // ATOMIC-011's separator set includes the `then`/`do`/`else` keywords;
        // executed_in_build must agree so the correlation is not a false
        // negative on real `if`/`for`-guarded executions (dual-LLM finding).
        assert!(executed_in_build(
            &pkgbuild_with_build("if [ -x x ]; then \"$srcdir/optimizer\"; fi"),
            "optimizer"
        ));
        assert!(executed_in_build(&pkgbuild_with_build("do \"$srcdir/linter\""), "linter"));
        assert!(executed_in_build(&pkgbuild_with_build("else \"$srcdir/minifier\""), "minifier"));
    }

    #[test]
    fn executed_in_build_rejects_dash_dot_and_equals_suffixes() {
        // Dual-LLM finding: `-`, `.`, `=` must NOT be treated as boundaries.
        // `linter-helpers`, `optimizer.c`, `linter=1` are not executions of the
        // exact disguise name and must not trip the correlation.
        assert!(!executed_in_build(&pkgbuild_with_build("; linter-helpers"), "linter"));
        assert!(!executed_in_build(&pkgbuild_with_build("linter=1"), "linter"));
        assert!(!executed_in_build(&pkgbuild_with_build("run $srcdir/linter-helpers"), "linter"));
        assert!(!executed_in_build(&pkgbuild_with_build("cc optimizer.c -o x"), "optimizer"));
        assert!(!executed_in_build(&pkgbuild_with_build("chmod +x \"$srcdir/optimizer.bin\""), "optimizer"));
    }

    #[test]
    fn chmod_preparation_is_not_execution() {
        // chmod +x prepares the helper but does not run it; executed_in_build
        // must NOT count it (ATOMIC-011's text rule covers the chmod itself).
        assert!(!executed_in_build(&pkgbuild_with_build("    chmod +x \"$srcdir/assembler\""), "assembler"));
        assert!(!executed_in_build(&pkgbuild_with_build("chmod 755 \"$srcdir/linter\""), "linter"));
    }

    #[test]
    fn executed_in_build_does_not_match_substring_names() {
        // "linter-helpers" / "optimizer.c" are not executions of "linter"/"optimizer".
        assert!(!executed_in_build(&pkgbuild_with_build("make linter-helpers"), "linter"));
        assert!(!executed_in_build(&pkgbuild_with_build("cc optimizer.c -o x"), "optimizer"));
        // build() body that never mentions the name.
        assert!(!executed_in_build(&pkgbuild_with_build("make && make install"), "minifier"));
    }

    // --- full-scanner integration (fake package vs legit Makefile project) --

    fn pkgbuild_text(build_body: &str) -> String {
        format!(
            "pkgname=trojan-pkg\npkgver=1.0\npkgrel=1\narch=('x86_64')\n\
             build() {{\n{body}\n}}\n",
            body = build_body
        )
    }

    #[tokio::test]
    async fn fake_package_with_embedded_elf_fires_atomic012() {
        // A package that ships a real compiled ELF named "optimizer" and runs it
        // in build() must fire ATOMIC-012 end-to-end through the real Scanner.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("PKGBUILD"), pkgbuild_text("  \"$srcdir/optimizer\""))
            .unwrap();
        // A genuine ELF payload under the disguise name.
        std::fs::write(
            root.join("optimizer"),
            [0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        )
        .unwrap();

        let scanner = crate::Scanner::with_defaults().unwrap();
        let result = scanner.scan_directory(root).await.unwrap();
        assert!(
            result.findings.iter().any(|f| f.id == "ATOMIC-012"),
            "fake ELF package must fire ATOMIC-012; got {:?}",
            result.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
        // ATOMIC-011 (text rule) also fires because the PKGBUILD executes it.
        assert!(
            result.findings.iter().any(|f| f.id == "ATOMIC-011"),
            "executed-in-build should also trip ATOMIC-011"
        );
    }

    #[tokio::test]
    async fn legit_makefile_project_does_not_fire_atomic012() {
        // A normal C project (Makefile + .c sources + configure script) must NOT
        // fire ATOMIC-012, even though it has ELF-looking compiled artifacts.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(
            root.join("PKGBUILD"),
            "pkgname=legit-pkg\npkgver=1.0\npkgrel=1\narch=('x86_64')\n\
             build() {\n  ./configure && make\n}\n",
        )
        .unwrap();
        std::fs::write(root.join("Makefile"), "all:\n\tcc main.c -o app\n").unwrap();
        std::fs::write(root.join("main.c"), "int main(){return 0;}\n").unwrap();
        std::fs::write(root.join("configure"), "#!/bin/sh\necho configuring\n").unwrap();
        // Even a compiled object/binary under a NON-disguise name must not fire.
        std::fs::write(root.join("app"), [0x7f, b'E', b'L', b'F', 2, 1, 1, 0]).unwrap();
        std::fs::write(root.join("main.o"), [0x7f, b'E', b'L', b'F', 2, 1, 1, 0]).unwrap();

        let scanner = crate::Scanner::with_defaults().unwrap();
        let result = scanner.scan_directory(root).await.unwrap();
        assert!(
            result.findings.iter().all(|f| f.id != "ATOMIC-012"),
            "legit Makefile project must NOT fire ATOMIC-012; got {:?}",
            result.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
    }
}
