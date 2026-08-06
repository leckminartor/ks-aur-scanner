# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
[Semantic Versioning](https://semver.org/).

## [2.3.0] - 2026-08-06

### Added — ATOMIC-011: Embedded ELF helper execution in build()/package() (no sudo)

A further Wave-3 (Aug 2026) Atomic Arch variant embeds compiled ELF binaries
directly into the PKGBUILD build script under a benign tool name (linter,
minifier, parser, assembler, translator, optimizer). The helper runs during
`makepkg` with **no network call and no npm/bun cache**, so it evades the
earlier delivery-based detection (ATOMIC-001/002). ATOMIC-005 already catches
the root-elevation form (`sudo "$srcdir/<helper>"`); ATOMIC-011 extends coverage
to the **sudo-free execution** and to the **`chmod +x` preparation step**.

- **ATOMIC-011 — Embedded ELF helper execution (no sudo)**: Flags a
  `build()`/`package()` step that executes a `$srcdir` source-tree file under a
  benign tool name as a command (start-of-line, or after `;`/`|`/`&`/`&&`/a
  newline, or a command-position keyword like `then`/`do`/`else`, or a subshell
  open) — but **not** as an argument to `install`/`cp`/`mv` (legitimate). Also
  flags the `chmod +x` preparation of such a helper, covering symbolic who forms
  (`u+x`, `ug+x`, `a+x`, `+x`), flag forms (`chmod -R +x`), and numeric modes
  (`chmod 755`). The tool name must be a complete path component, so
  `optimizer.bin` / `linter-helper` do not false-fire.

### Notes

- Legitimate PKGBUILDs do not execute arbitrary source files under these tool
  names during the build phase — they use `make`/`configure` or `install` them.
- The `${srcdir}` brace form, indentation, and `chmod` who/numeric variants are
  all handled; the undo/redo false-positive (a helper that is later removed)
  and the `optimizer.bin` suffix false-positive are explicitly excluded.

### Verification

- **Dual-LLM code review** (code-quality + security-architecture) — all HIGH
  and CRITICAL findings addressed (indentation, `${srcdir}` brace, undo/redo
  FP, `chmod` who/numeric, `optimizer.bin` FP).
- **Tested in a fresh Arch Distrobox container** (`aur-shield-test`,
  `archlinux:latest`): `cargo build --release --workspace` + `cargo test`.
- Workspace test suite: **233 tests green**.

## [2.2.0] - 2026-08-05

### Added — "Atomic Arch Wave 3" two-stage loader/stealer coverage (July/Aug 2026)

A third wave of the Atomic Arch campaign triggered the AUR push lockdown on
2026-08-01. Unlike Waves 1-2 (npm/bun delivery), this campaign uses a two-stage
attack: a C loader run as **root via `sudo "$srcdir/optimizer"` inside `build()`**
— *before* any pre-install hook can scan it — which bootstraps a private Tor
client, dials a `.onion` C2, downloads a Rust infostealer/RAT/SSH-worm, and
launches it via `systemd-run --user --scope`. Analysis: orhun/aur-report.md,
ysf/stage2.md, IFIN Threat Intel thread 698.

- **ATOMIC-005 — Root-privileged build-time helper execution**: Flags any
  `sudo "$srcdir/<file>"` in a PKGBUILD's build/package phase. This is the exact
  Wave-3 loader vector — root elevation before any hook fires.
- **ATOMIC-006 — Private Tor client / onion C2 (stage-1 loader)**: Detects the
  loader-specific Tor bootstrap (`--DataDirectory`/`--SocksPort` under /tmp,
  `LD_LIBRARY_PATH=/tmp/tb`) and the known Wave-3 C2 onion
  `p4ayykxcrxfyzrgfbbkazernntjbz43hgclrheguylzd7kijmtce6zqd.onion`. Generic Tor
  usage (`archive.torproject.org` download, `Bootstrapped 100%`) is deliberately
  NOT flagged to avoid false positives.
- **ATOMIC-007 — Stage-2 drop paths / systemd-run launch**: Detects
  `/dev/shm/.agent.bin`, `/tmp/linux-x86_64/agent`, `systemd-run --user --scope`,
  and `loginctl enable-linger`.
- **ATOMIC-008 — Tor-exfil argv[0] masquerade / xattr marker**: Detects the
  `dbus-daemon` process-masquerade, `AllowSingleHopCircuits`, and the
  `security.selinux` reinfection-marker (now matched with its `0x01` value).
- **ATOMIC-009 — SSH key exfil / lateral movement (SSH worm)**: Detects
  `~/.ssh/id_rsa`/`id_ed25519` reads, `authorized_keys`/`known_hosts` tampering,
  and `ssh`/`scp` with `BatchMode`/`StrictHostKeyChecking=no`.
- **ATOMIC-010 — Cloud metadata endpoint exfiltration**: Detects the link-local
  IAM metadata endpoint (`169.254.169.254`, `169.254.170.2`,
  `metadata.google.internal`, `latest/meta-data`).
- **IOC database**: New campaign `atomic-arch-2026-08` with the C2 onion domain
  and 3 known payload hashes (2 stage-1 loaders, 1 stage-2 agent).

### Notes

- Generic file names (`agent`, `optimizer`) were intentionally **not** added to
  the `[files]` IOC map to avoid false positives — they are caught by the
  ATOMIC-005..008 content rules instead.
- `torproject.org` / `archive.torproject.org` / `Bootstrapped 100%` are
  **not** content-rule patterns — they are legitimate Tor usage; network-level
  blocking of the loader's bundle host lives in arch-shield's C2 blocklist.

### Verification

- **Dual-LLM code review** (code-quality + security-architecture) — all HIGH and
  CRITICAL findings addressed (sha256 IOC matching, FP on legitimate Tor/SELinux
  usage, SSH-worm and cloud-metadata coverage).
- **Tested in a fresh Arch Distrobox container** (`aur-shield-test`,
  `archlinux:latest`): build + install `aur-scan 2.2.0`, then scanned simulated
  Wave-3 PKGBUILDs — ATOMIC-005/006/007/009/010 fire correctly; legitimate Tor
  usage and clean PKGBUILDs stay clean (exit 0, zero ATOMIC findings).
- Workspace test suite: **275 tests green**.

## [2.1.0] - 2026-07-10

### Added — Atomic Arch supply-chain attack coverage (June 2026)

The June 2026 "Atomic Arch" AUR supply-chain attack unfolded in five waves, each
mutating to evade prior detection methods. This release closes coverage gaps
identified against all five waves.

- **Wave 1 & 2 — npm `atomic-lockfile` / bun `js-digest`**: Already covered by
  ATOMIC-001 (malicious package names) and ATOMIC-002 (npm/bun in install hooks).

- **Wave 3 — Obfuscated `bun add nextfile-js`**: Shell-obfuscated payloads
  (ANSI-C `$'\x..'` + empty-quote concatenation) were already caught by the
  de-obfuscation engine, but `nextfile-js` was missing from ATOMIC-001's
  known-malicious package list. **Added `nextfile-js` to ATOMIC-001**.

- **Wave 4 — ALPM `.hook` file delivery**: Attackers delivered payloads in
  packaged `.hook` files alongside (or instead of) `.install` scripts, escaping
  scanners that only look at `.install` files. **Added full `.hook` file scanning**
  — the scanner now discovers `<pkg>.hook` files in the package directory and
  scans them with the same rule engine (FileType::HookFile). Malicious `.hook`
  files from the campaign (e.g. `archlinux-themes-slim.hook`, `autologin.hook`)
  would now be caught.

- **Wave 5 — Shell-RC injection ("Russian spam")**: Copycat attackers appended
  offensive messages to shell startup files (`/etc/bash.bashrc`, `/etc/zsh/zshrc`,
  `/etc/fish/config.fish`, `/etc/profile.d/*.sh`). **Expanded ENV-003** to cover
  all target files from the campaign: fish config paths, `/etc/zsh/zshrc`,
  `/etc/zsh/zprofile`, `~/.zprofile`, `~/.zshenv`, and `/etc/profile.d/`.

- **Sudo credential-stealer shim**: The `~/.local/bin/sudo` shim (SHA256
  fd485233…) documented as a campaign IOC was undetected. **Added ATOMIC-004**
  to detect this PATH-shadowing credential theft mechanism.

### Changed

- ENV-003 regex patterns expanded to cover fish shell config and additional
  zsh/profile.d paths targeted by the Russian-spam wave. Recommendation text
  now includes compromise guidance.

## [2.0.0] - 2026-06-17

Major release: optional, opt-in threat-intelligence lookups (VirusTotal +
URLhaus), an active verdict cache, broader AUR-helper coverage (cache discovery
+ shell wrappers + a Nushell integration), and a global `--no-color` flag. The
default scan is unchanged — fully offline and static; threat intelligence stays
off until you enable it and supply your own keys.

### Added — opt-in threat intelligence

- **VirusTotal & URLhaus lookups, wired in for real.** The previously inert
  provider stubs are now working: with `enable_threat_intel` set and a key
  supplied (config or `VT_API_KEY`/`VIRUSTOTAL_API_KEY`/`URLHAUS_AUTH_KEY`), a new
  networked analyzer checks each declared `sha256sums` against VirusTotal and each
  `source=` URL against abuse.ch/URLhaus, emitting `TI-VT-001` / `TI-URLHAUS-001`
  on a malicious verdict. **Off by default** — a default scan stays fully
  offline/static. Only data already public in the PKGBUILD (hashes, source URLs)
  is ever transmitted; every lookup fails open so a provider outage never blocks a
  scan. All third-party network code is isolated in a single auditable file
  (`threat_intel/remote.rs`). URLhaus requires the now-mandatory abuse.ch
  `Auth-Key`.

  The VirusTotal-by-hash approach is credited to **@SuitablyMysterious**, whose
  `vt_lookup` in [PR #9](https://github.com/KiefStudioMA/ks-aur-scanner/pull/9)
  was the reference implementation.

- **Verdict caching is now active.** The hardened, MAC-authenticated `DiskCache`
  (owner-only dir, per-user keyed integrity) — previously built but unwired — now
  caches threat-intel verdicts, so repeat lookups respect VirusTotal's 4-req/min
  public quota. Gated by `CacheConfig`; lookups are also capped per scan.

### Added — broader AUR helper coverage

- **`system` audit and the pacman hook now cover every maintained AUR helper.**
  Cache discovery spans yay, paru, pikaur, aura, pakku, trizen, aurutils, rua, and
  pat-aur — at each helper's real PKGBUILD location (e.g. pikaur's
  `~/.local/share/pikaur/aur_repos`, rua's `~/.config/rua/pkg`, trizen's
  `~/.cache/trizen/sources`), with XDG `*_HOME` overrides honored.
- **Shell integration wraps more helpers** ([#6](https://github.com/KiefStudioMA/ks-aur-scanner/issues/6); diagnosis from [@nikoraasu](https://github.com/nikoraasu) in [#12](https://github.com/KiefStudioMA/ks-aur-scanner/issues/12)).
  `pikaur`, `trizen`, and `pakku` join `paru`/`yay` as pre-build gates (they share
  pacman's `-S`/`-Syu` grammar); helpers with a different model (`aura -A`, and the
  subcommand tools aurutils/rua/pat-aur) are covered by the pacman hook instead.
- **Nushell integration** (`install/integration.nu`, [#5](https://github.com/KiefStudioMA/ks-aur-scanner/issues/5)) — routes
  helper installs through the `aur-scan-wrap` gate; honors `AUR_SCAN_ENABLED=0` and
  provides `<helper>-unsafe` bypasses. Verified on nushell 0.113.
- **pacman hook** now sets `NeedsTargets`, so the transaction's package names reach
  the hook (it reads targets from stdin to locate each PKGBUILD).

### Changed

- Added a global `--no-color` flag; colored output also honors the `NO_COLOR`
  environment variable and auto-disables when not writing to a terminal.

## [1.1.0] - 2026-06-15

Stable promotion of the 1.1.0 release-candidate line, plus a second hardening
wave that closes the residual evasion classes surfaced by an adversarial
self-audit. **Stable.**

### Detection — evasion classes closed

- **Variable-indirection (taint pass).** A fetch/exec hidden behind a shell
  variable (`dl=curl; $dl …`, a `$(printf …)`-assembled command name) is now
  resolved and matched in addition to the raw and de-obfuscated forms — it used to
  evade every rule. Resolution only ever adds a finding, never suppresses one.
- **Case-insensitive analyzers.** The structural analyzers (privilege, remote-exec,
  deep, source) match command/shell/interpreter tokens case-insensitively, so a
  cased-up payload no longer slips a finding. Canonical-casing tokens (env-var
  NAMEs, the `R` interpreter, base64/hex alphabets) stay case-sensitive to avoid
  false positives.
- **Host-aware URL/IOC matching.** Domain and source-host checks parse the real URL
  authority instead of a naive substring, closing a `github.com\@evil.tld` /
  defanged-host evasion and a path-segment-as-host false positive.
- **Supply-chain & packaging-metadata analyzer.** New structural checks over
  `provides`/`replaces`/`epoch`/`backup`/`install`/`validpgpkeys`/checksums
  (dependency confusion, core-package displacement, signature theatre, sensitive
  `backup=`, malformed hashes).
- The printed-message filter is quote-aware: a `;` inside a quoted `echo` no longer
  trips `HIDDEN-001`.

### Hardening

- **Cache verdicts are authenticated** with a per-user keyed MAC — a local writer
  can no longer flip a malicious verdict to benign; a MAC failure is a miss, not
  trusted data.
- The `makepkg` build environment is allowlisted (a poisoned `PATH`/`LD_*`/`GIT_*`
  cannot redirect trusted helpers); `--force` can never override an *unscannable*
  package; a `--local` scan only attributes a cached verdict to a node whose name
  provably matches.
- A community rule that omits `file_types` now defaults to the scanned types
  instead of loading inert.

### Quality

- A **self-adversarial evasion fuzzer** runs as a release gate: every malicious
  fixture is mutated through a library of semantics-preserving evasion transforms
  and the gate must still block each variant — a slip fails the build.

### Credits

The install-hook package-manager detection (`ATOMIC-002`) and the de-obfuscation
pass this release hardens were prompted by community threat reports:
[@LunarEclipse363](https://github.com/LunarEclipse363)
([#2](https://github.com/KiefStudioMA/ks-aur-scanner/issues/2) — the
orphaned-package takeover that pulled the `atomic-lockfile` infostealer through an
install hook) and [@zebulon2](https://github.com/zebulon2)
([#10](https://github.com/KiefStudioMA/ks-aur-scanner/issues/10) — the obfuscated
`bun add` (`nextfile-js`) variant the de-obfuscation pass now sees through).

## [1.1.0-rc3] - 2026-06-15

Security-hardening release: an adversarial pre-ship review of the rc2 code closed
six real defects across the gate, parser, and detection layers, plus an
exhaustive expansion of shell/interpreter download-exec coverage. **Release
candidate.**

### Gate — fail closed
- The AUR-membership classifier no longer treats a network/lookup error as
  "not an AUR package" (which could let an install proceed unscanned); an
  indeterminate result now fails closed and is scanned. The `install` consent
  prompt requires a TTY — a piped `y` no longer counts as consent.

### Parser — no silent evasion, no panic
- Closed a quote-state desync between the array terminator and the inline-comment
  stripper that could silently drop a crafted `source=()`/`sha256sums=()`
  continuation line, hiding a source from every analyzer. An unterminated array is
  now flushed to the analyzers (and warned), never dropped.
- Fixed a panic on a CRLF + multibyte `.install` (byte offset could land
  mid-codepoint).

### Detection
- The privilege analyzer now shares the informational-line filter, so a printed
  `sudo`/`setcap`/`sudoers` message or heredoc no longer raises a Critical finding.
- The printed-message filter is now **quote-aware**: a `;`/`|`/`&`/`>` *inside* a
  quoted `echo`/`msg` string is literal text, so a benign note like
  `echo "config lives in ~/.config; ..."` no longer trips `HIDDEN-001`. An
  unquoted chain (`echo x; touch ~/.evilrc`) and in-string command substitution
  (`"$(curl …)"`) are still scanned.
- De-obfuscation now decodes 2-char quote-splitting and backslash escapes, catches
  `dash` and other shells the old alternation missed, and runs in the deep /
  remote-exec / IOC analyzers too.
- **Exhaustive download-exec sink coverage** — every common shell and interpreter
  reachable via `curl | …`, `<(curl)`, `-c/-e/-r "$(curl)"`, here-strings, path
  prefixes (`/bin/sh`), launchers (`busybox`/`env`/…), and double-launchers
  (24 shells + 20+ interpreters). `npx`/`bunx` lifecycle runners (`ATOMIC-002`).
  New `EXEC-006` (`sqlite3 .shell/.system/.import`) and `EXEC-007`
  (`make -f -` / `make -f /dev/stdin`).
- `HIDDEN-002`/`INSTALL-002` now require an execution context (no longer fire on
  `TMPDIR=/tmp/…`, `mktemp -d /tmp/…`, `./configure`).

### Pacman hook
- The privilege-drop decision/guard logic is now test-covered: it refuses a uid-0
  *or* gid-0 drop target, refuses a symlinked/non-regular PKGBUILD, and fails
  closed on a scan error or a critical finding.

## [1.1.0-rc2] - 2026-06-14

Proactive detection expansion, driven by a live obfuscated AUR campaign and an
adversarial gap analysis of the catalog. **Release candidate.**

### Anti-evasion (the multiplier)

- **De-obfuscation pass.** A new wave hid a `bun add <js-payload>` in a
  `post_install` hook using ANSI-C quoting (`$'\x63'`) and adjacent-quote
  word-splitting (`"b"'u''n'`), which evaded the targeted rules — rc1 caught it
  only as a generic high "hex payload." The scanner now **decodes** ANSI-C
  escapes and **collapses** quote-splitting, and runs *every* rule against the
  decoded text. The whole catalog now resists this evasion at once: that sample
  is correctly flagged **critical** (`ATOMIC-002`, package-manager-in-install-hook).
- `OBF-006` flags the quote-splitting technique itself; `OBF-007/008/011` add
  printf-assembly, base32/16 decode, and interpreter here-strings.

### Detection — +28 rules across six threat classes (catalog 72 → 106)

- **Reverse/bind shells:** `SHELL-005..011` — perl, php, ruby/lua/awk, node,
  openssl `s_client`, `mkfifo` backpipe, busybox-nc/telnet/ncat-ssl.
- **Exfiltration:** `EXFIL-004` (DNS), `EXFIL-006/007` (curl/wget upload),
  `EXFIL-008` (Slack/Teams webhooks), `EXFIL-009` (file-drop/tunnel hosts),
  `CRED-004/005/008` (cloud/CI creds, keyrings/wallets, env dump).
- **Auth/system tampering:** `PRIV-007/008` (privileged account, password),
  `TAMPER-001/002/005/011/013/017` (auth-db write, doas/NOPASSWD, PAM, pacman
  `SigLevel=Never`, disabling security controls, CA trust anchor).
- **Supply-chain trust:** `TRUST-001/002` (pacman-key / gpg import),
  `DEP-003` (index/registry override), `SRC-009` (obfuscated IP in URL).
- **RCE:** `EXEC-002` (`sh -c "$(curl)"`), `EXEC-005` (detached `setsid`/`nohup`).

### Other

- `aur-scan install` now tidies its own build directory after a successful
  install (`--keep-build` to retain).
- Packaging: `options=('!debug' '!strip')` — the release binaries are already
  stripped by cargo, so makepkg's split-debug + re-strip passes were redundant
  (and produced an empty `-debug` package + `gdb-add-index`/libfakeroot noise).
- The fail-closed wrapper and the privilege-dropping pacman hook gained unit
  tests for their deny/refuse/validation paths.

## [1.1.0-rc1] - 2026-06-13

Security-hardening release resolving a full security & quality audit of the
scanner. **Release candidate** — see "Behavior changes" below before upgrading
automation, and the validation checklist in the PR before promoting to stable.

### ⚠️ Behavior changes (read before upgrading)

- **The scanner now fails *closed*.** The `paru`/`yay` wrapper and the pacman
  hook previously continued past a fetch/scan error, a timeout, or a
  non-interactive prompt; they now **deny** in those cases. If you drive
  `paru`/`yay` from a script, cron, or CI (no TTY), an install that cannot be
  fully analyzed will be refused rather than silently proceeding. This is
  intentional — a security gate that fails open is not a gate.
- **`scan --format json` / `--format sarif` now emit only the machine document
  on stdout.** The human-readable summary moved to **stderr**, so
  `aur-scan scan --format json | jq` works. If you were scraping the summary
  text out of stdout, read stderr instead (or use the JSON fields).

### Security

- **Input validation chokepoint** for package names/bases: illegal identifiers
  are rejected before they can become URL path segments or filesystem paths,
  closing a path-traversal vector (`package_base` → `remove_dir_all`) and
  request-injection into the AUR RPC.
- **Network hardening:** redirects refused, HTTPS-only enforced, response bodies
  size-capped (streaming), and all RPC URLs percent-encoded.
- **Pacman hook drops root** (supplementary groups → gid → uid, verified
  irreversible) before reading user cache files, validates names, and refuses
  symlinked PKGBUILDs.
- **Detection-evasion fixes:** backslash-newline line-continuation splicing;
  quote- and comment-aware brace scanning (no more `echo "}"` / `# }`
  truncation); broadened reverse-shell (`/dev/(tcp|udp)/<host>`) and bare
  crypto-address detection; checksum SKIP-laundering across all hash arrays.
- Dependency advisory **RUSTSEC-2026-0007** resolved (`bytes` → 1.11.1).

### Added

- `SRC-007`: warns when a VCS source is not pinned to a commit (Low — a
  reproducibility nudge, since branch-tracking is normal for `-git` packages).
- `Severity::is_at_least()` gate helper with an order-pinning test.
- CLI integration test suite that runs the real binary against the PKGBUILD
  fixtures (JSON/SARIF validity, detection matrix, catalog coverage, exit codes).
- CI (format, clippy-as-error, full tests, release build) and `cargo-deny`
  supply-chain gating, plus a weekly advisory scan.
- The rolling `-git` package now verifies the signed HEAD commit at build time.

### Fixed

- **False positive:** a printed `note "...~/.config/..."` message in an install
  script no longer trips `HIDDEN-001` (it mentions a path; it does not write
  one) — observed on `google-chrome` and `visual-studio-code-bin`.
- `scan` machine-format output no longer corrupted by the summary footer.
- Parser: `source+=(...)` appends are no longer dropped; inline comments are
  handled quote-aware (a `#commit=` fragment in a quoted value is preserved);
  single-line function bodies are captured.
- Cache writes are atomic (`0600`) in an owner-only (`0700`) directory, entries
  are key-bound, and a corrupt entry is a miss rather than trusted data.
- Provenance store distinguishes an absent baseline from a corrupt one (the
  latter is preserved as `.corrupt` and warned, not silently reset).
- Removed a panicking `AurClient::default()` and a response `unwrap`.

### Notes

- The `--locked` updates to the tagged-package PKGBUILDs live in their own AUR
  repositories and are released separately.

## [1.0.3]

See the project history prior to the introduction of this changelog.

[2.0.0]: https://github.com/KiefStudioMA/ks-aur-scanner/releases/tag/v2.0.0
[1.1.0-rc1]: https://github.com/KiefStudioMA/ks-aur-scanner/releases/tag/v1.1.0-rc1
