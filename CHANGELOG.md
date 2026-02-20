# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.3] - 2026-02-20

### Added
- **Recovery CLI Tool (`vlt_admin_cli`)**: A standalone tool for direct database management and user recovery, bypassing the API server.
- **SBP Protocol Specification (`SBP_SPEC.md`)**: Formalized the Structured Binary Protocol (SBP) to solve Windows "quoting hell" and enhance AI-driven automation.
- **Security Status Report (`SECURITY_STATUS_REPORT.md`)**: Transparent disclosure of current security implementation, risks, and known vulnerabilities.
- **Admin System Redesign Plan**: Documented the architectural shift toward a local-first, recovery-focused management model.

### Changed
- Refined the roadmap to prioritize "Stand-alone Integrity" and exclude complex MFA dependencies.
- Added safety warnings regarding TPM manipulation and remote BitLocker lockout risks.
- **Security Hardening**: Implemented authentication retry limits (`SEC-01`) and session idle timeouts to prevent brute-force and resource exhaustion.
- **IPC Safety**: Fixed IPC message length framing (`ALGO-01`) to prevent buffer issues in service-worker communication.
- **PowerShell Sanitization**: Improved command argument sanitization (`SEC-04`) to prevent shell injection.
- **Process Management**: Replaced `wmic` calls with `tasklist` and native API queries (`ALGO-03`) for better reliability and performance.

### Security
- Acknowledged approximately 10 known vulnerabilities currently under remediation.
- Recommended SSH key passphrases as a practical alternative to complex MFA.
- Conducted safety review of all `unsafe` blocks and verified `UserToken` thread safety.

## [Purified Restoration] - 2026-02-19

### Added
- **Resilience Layer**: Added `worker_pid` and `pipe_name` to DB `sessions` table for session tracking across service restarts.
- **Automation Scripts**: Introduced `Install-WinNativeSSH.ps1`, `Enable-WSL.ps1`, and `Setup-DefenderDebugExclusions.ps1` for one-click setup.
- **Nushell Integration**: Added `Get-Nushell.ps1` to facilitate modern shell deployment.

### Fixed
- **IPC Standardization**: Fixed Serde deserialization issues by explicitly tagging Enum variants (standardizing on `SCREAMING_SNAKE_CASE` fixes).
- **Core Stability**: Removed legacy `m4_fast` impurities and simplified worker main loop.
- **Path Consistency**: Standardized database paths to absolute paths relative to the executable.

## [v0.6.0-Draft] - 2026-02-18

### Added
- **SBP Evolution**: Introduced `upgrade-sbp` versioned handshake and `sbp-spec` self-documentation command for AI agents.
- **Distribution Strategy**: Deprecated internal `download` command in favor of standard **SCP** for client distribution, maintaining protocol purity.

## [v0.5.0] - 2026-02-16

### Changed
- **russh 0.40 Migration**: Fully adapted to `russh` 0.40 API changes (PublicKey path and Base64 trait changes).
- **ACL Diagnostics**: Fixed `WindowsUserInfo` handling to support `vlt-admin check-permissions`.

## [v0.4.0] - 2026-02-16

### Added
- **CI/CD Foundation**: Introduced GitHub Actions for automatic build/test on Windows and Linux.
- **vlt-worker Enhancements**: Added `env` internal command and improved `tasklist` with memory/session info.

## [v0.3.0] - 2026-02-15

### Added
- **Command Interception**: Implemented internal `whoami`, `where`, and `tasklist` in `vlt-worker` to bypass external process dependencies.
- **Service Stability**: Implemented SSH channel EOF/Close handlers for immediate worker cleanup.
