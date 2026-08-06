//! IOC analyzer: matches scanned content against the local IOC database.
//!
//! Complements the heuristic pattern engine. Where the pattern engine reasons
//! about *behavior* ("an install hook runs npm"), this analyzer matches known
//! *indicators* ("the package atomic-lockfile", "the file scales.bpf.c"),
//! catching hijacks that otherwise look clean.

use super::SecurityAnalyzer;
use crate::error::Result;
use crate::rules::informational_lines;
use crate::textutil::deobfuscate_text;
use crate::threat_intel::IocDatabase;
use crate::types::{AnalysisContext, Category, Finding, Location, Severity};
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::sync::Arc;

/// Analyzer that matches content against the IOC database.
pub struct IocAnalyzer {
    db: Arc<IocDatabase>,
}

impl IocAnalyzer {
    /// Create an analyzer backed by the given IOC database.
    pub fn new(db: Arc<IocDatabase>) -> Self {
        Self { db }
    }

    fn finding_for(
        &self,
        context: &AnalysisContext,
        file: &std::path::Path,
        hit: &crate::threat_intel::IocHit,
    ) -> Finding {
        let campaign_name = hit
            .campaign
            .as_deref()
            .and_then(|id| self.db.campaign(id))
            .map(|c| c.name.clone());
        let campaign_suffix = campaign_name
            .as_ref()
            .map(|n| format!(" (campaign: {n})"))
            .unwrap_or_default();

        Finding {
            id: "IOC-001".to_string(),
            severity: Severity::Critical,
            category: Category::MaliciousCode,
            title: format!("Known IOC: {} '{}'", hit.kind.label(), hit.value),
            description: format!(
                "Content matches a known indicator of compromise: {} '{}'{}.",
                hit.kind.label(),
                hit.value,
                campaign_suffix
            ),
            location: Location {
                file: file.to_path_buf(),
                line: Some(hit.line),
                column: None,
                snippet: None,
            },
            recommendation:
                "Do NOT build. This matches a known-malicious indicator; treat the host as \
                 compromised if already built and rotate credentials."
                    .to_string(),
            cwe_id: Some("CWE-506".to_string()),
            metadata: serde_json::json!({
                "ioc_kind": format!("{:?}", hit.kind),
                "ioc_value": hit.value,
                "campaign": hit.campaign,
                "context": context.file_path.to_string_lossy(),
            }),
        }
    }
}

impl IocAnalyzer {
    /// Scan one file's text against the IOC database, matching both the raw text
    /// and its de-obfuscated form so an indicator hidden by quote-splitting /
    /// ANSI-C escaping (e.g. `"ato""mic-lockfile"`) is still caught (defect #6c).
    /// De-obfuscation preserves line numbers, so a hit reports its real line; the
    /// raw and decoded passes are deduplicated by (kind, value, line) so an
    /// indicator that needed no decoding is reported once.
    fn scan_file(
        &self,
        context: &AnalysisContext,
        file: &std::path::Path,
        text: &str,
        findings: &mut Vec<Finding>,
    ) {
        // Blank out comment lines and printed/informational lines (a
        // non-redirected heredoc body or a pure `echo`/`msg "..."` print) before
        // matching, so a package that merely DOCUMENTS an indicator (e.g. a
        // post_install note "do not install atomic-lockfile") does not raise an
        // IOC finding. Blanking (not deleting) preserves line numbers so a real
        // hit still reports its true line.
        let scannable = mask_informational(text);
        let mut seen: HashSet<(String, String, usize)> = HashSet::new();
        let mut collect = |content: &str, findings: &mut Vec<Finding>| {
            for hit in self.db.scan_content(content) {
                let key = (format!("{:?}", hit.kind), hit.value.clone(), hit.line);
                if seen.insert(key) {
                    findings.push(self.finding_for(context, file, &hit));
                }
            }
        };
        collect(&scannable, findings);
        let decoded = deobfuscate_text(&scannable);
        if decoded != scannable {
            collect(&decoded, findings);
        }
    }
}

/// Replace comment lines and printed/informational lines with empty lines,
/// preserving the total line count (so IOC hit line numbers stay accurate). Uses
/// the shared `informational_lines` pre-filter over physical lines, since the IOC
/// database reports physical line numbers.
fn mask_informational(text: &str) -> String {
    let phys: Vec<&str> = text.lines().collect();
    let informational = informational_lines(&phys);
    phys.iter()
        .enumerate()
        .map(|(i, l)| {
            if informational[i] || l.trim_start().starts_with('#') {
                ""
            } else {
                *l
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[async_trait]
impl SecurityAnalyzer for IocAnalyzer {
    async fn analyze(&self, context: &AnalysisContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        self.scan_file(
            context,
            &context.file_path,
            &context.pkgbuild.raw_content,
            &mut findings,
        );

        if let Some(install) = &context.install_script {
            self.scan_file(context, &install.path, &install.content, &mut findings);
        }

        // File-hash IOC matching: a PKGBUILD/install script does not contain its
        // own SHA-256 in its text, so a `db.sha256` payload-hash indicator (e.g.
        // the meshcore-open-git malicious PKGBUILD) can never fire via
        // scan_content. Hash the actual file bytes and compare against the
        // database so those indicators are actually effective, not advisory.
        self.scan_file_hash(context, &context.file_path, &mut findings);
        if let Some(install) = &context.install_script {
            self.scan_file_hash(context, &install.path, &mut findings);
        }

        Ok(findings)
    }

    fn name(&self) -> &str {
        "ioc"
    }
}

impl IocAnalyzer {
    /// Compute the SHA-256 of a scanned file's bytes and, if it matches a known
    /// `db.sha256` payload-hash indicator, emit an IOC finding. Distinct from
    /// `scan_file`, which matches indicator strings *inside* the text.
    fn scan_file_hash(
        &self,
        context: &AnalysisContext,
        file: &std::path::Path,
        findings: &mut Vec<Finding>,
    ) {
        // Only hash files we have actual bytes for. In static scans the content
        // is parsed from a string; resolve the on-disk path when it exists.
        let Ok(bytes) = std::fs::read(file) else {
            return;
        };
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let digest = hex_digest(&hasher.finalize());

        if let Some(campaign) = self.db.match_sha256(&digest) {
            let campaign_name = self.db.campaign(campaign).map(|c| c.name.clone());
            let campaign_suffix = campaign_name
                .map(|n| format!(" (campaign: {n})"))
                .unwrap_or_default();
            findings.push(Finding {
                id: "IOC-001".to_string(),
                severity: Severity::Critical,
                category: Category::MaliciousCode,
                title: format!("Known IOC: SHA-256 payload hash '{}'", digest),
                description: format!(
                    "The file's SHA-256 matches a known indicator of compromise: \
                     malicious payload hash '{digest}'{campaign_suffix}."
                ),
                location: Location {
                    file: file.to_path_buf(),
                    line: None,
                    column: None,
                    snippet: None,
                },
                recommendation:
                    "Do NOT build. This file matches a known-malicious payload hash; treat \
                     the host as compromised if already built and rotate credentials."
                        .to_string(),
                cwe_id: Some("CWE-506".to_string()),
                metadata: serde_json::json!({
                    "ioc_kind": "Sha256",
                    "ioc_value": digest,
                    "campaign": campaign,
                    "context": context.file_path.to_string_lossy(),
                }),
            });
        }
    }
}

/// Render a SHA-256 digest as a lowercase hex string.
fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{PkgbuildParser, StaticParser};
    use crate::types::ScanConfig;
    use std::path::PathBuf;

    #[tokio::test]
    async fn flags_npm_payload_in_pkgbuild() {
        let parser = StaticParser::new();
        let pkgbuild = parser
            .parse("pkgname=x\npkgver=1\npkgrel=1\npackage() {\n npm install atomic-lockfile\n}\n")
            .unwrap();
        let context = AnalysisContext {
            pkgbuild,
            install_script: None,
            hook_file: None,
            config: ScanConfig::default(),
            file_path: PathBuf::from("PKGBUILD"),
        };
        let analyzer = IocAnalyzer::new(Arc::new(IocDatabase::embedded()));
        let findings = analyzer.analyze(&context).await.unwrap();
        assert!(findings.iter().any(|f| f.id == "IOC-001"));
    }

    #[tokio::test]
    async fn flags_obfuscated_ioc_and_does_not_double_report() {
        // Defect #6c: an IOC hidden by quote-splitting must be caught via the
        // de-obfuscated pass; a plain IOC on another line is reported exactly once
        // (the raw and decoded passes are deduplicated).
        let parser = StaticParser::new();
        let pkgbuild = parser
            .parse(
                "pkgname=x\npkgver=1\npkgrel=1\npackage() {\n npm install \"ato\"\"mic-lockfile\"\n bun add js-digest\n}\n",
            )
            .unwrap();
        let context = AnalysisContext {
            pkgbuild,
            install_script: None,
            hook_file: None,
            config: ScanConfig::default(),
            file_path: PathBuf::from("PKGBUILD"),
        };
        let analyzer = IocAnalyzer::new(Arc::new(IocDatabase::embedded()));
        let findings = analyzer.analyze(&context).await.unwrap();
        // The obfuscated atomic-lockfile is caught only after de-obfuscation.
        assert!(
            findings
                .iter()
                .any(|f| f.metadata["ioc_value"] == "atomic-lockfile"),
            "obfuscated IOC must be caught: {findings:?}"
        );
        // The plain js-digest indicator is reported exactly once, not duplicated
        // by the second (decoded) pass.
        let js_digest = findings
            .iter()
            .filter(|f| f.metadata["ioc_value"] == "js-digest")
            .count();
        assert_eq!(
            js_digest, 1,
            "plain IOC must not be double-reported: {findings:?}"
        );
    }

    #[tokio::test]
    async fn documented_ioc_in_printed_message_not_flagged() {
        // Task 4050a: a printed warning that merely NAMES an indicator (e.g. a
        // post_install note) must not raise IOC-001 — only executed lines count.
        let parser = StaticParser::new();
        let pkgbuild = parser
            .parse(
                "pkgname=x\npkgver=1\npkgrel=1\npackage() {\n echo \"warning: do not install atomic-lockfile\"\n}\n",
            )
            .unwrap();
        let context = AnalysisContext {
            pkgbuild,
            install_script: None,
            hook_file: None,
            config: ScanConfig::default(),
            file_path: PathBuf::from("PKGBUILD"),
        };
        let analyzer = IocAnalyzer::new(Arc::new(IocDatabase::embedded()));
        let findings = analyzer.analyze(&context).await.unwrap();
        assert!(
            !findings.iter().any(|f| f.id == "IOC-001"),
            "a printed message naming an IOC must not raise IOC-001: {findings:?}"
        );
    }

    #[tokio::test]
    async fn file_hash_ioc_matches_known_payload_hash() {
        // The file-hash hook closes the "file hash never appears in text"
        // detection escape: a scanned file whose on-disk SHA-256 equals a known
        // `db.sha256` payload hash must raise IOC-001 even though its text does
        // not reference the hash. We write a temp file with the known
        // ~/.local/bin/sudo shim content hash (fd485233…) and scan it.
        use crate::threat_intel::ioc::IocDatabase;

        let tmp = std::env::temp_dir().join(format!("aur-ioc-hash-test-{}", std::process::id()));
        // Any content is fine — we assert on the DB-hash match mechanism by
        // injecting the computed hash into a fresh DB.
        std::fs::write(&tmp, b"#!/bin/sh\nexec /usr/bin/sudo -n true\n").unwrap();

        let mut db = IocDatabase::embedded();
        // Compute the file's real sha256 and register it as a known payload hash.
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(std::fs::read(&tmp).unwrap());
        let hex: String = hasher.finalize().iter().map(|b| format!("{b:02x}")).collect();
        db.sha256.insert(hex.clone(), "atomic-arch-2026-06".to_string());

        let parser = StaticParser::new();
        let pkgbuild = parser
            .parse("pkgname=x\npkgver=1\npkgrel=1\npackage() { :; }\n")
            .unwrap();
        let context = AnalysisContext {
            pkgbuild,
            install_script: None,
            hook_file: None,
            config: ScanConfig::default(),
            file_path: tmp.clone(),
        };
        let analyzer = IocAnalyzer::new(Arc::new(db));
        let findings = analyzer.analyze(&context).await.unwrap();
        assert!(
            findings
                .iter()
                .any(|f| f.id == "IOC-001" && f.metadata["ioc_value"] == hex),
            "file-hash IOC must fire on a matching on-disk payload hash: {findings:?}"
        );

        let _ = std::fs::remove_file(&tmp);
    }
}
