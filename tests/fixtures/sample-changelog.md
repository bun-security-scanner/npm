# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

### Changed

### Deprecated

### Removed

### Fixed

### Security

## [1.0.1] - 2025-01-03

### Added
- Automated CHANGELOG generation from conventional commits in release workflow
- Comprehensive repository state validation before releases
- Package content verification before npm publishing
- Atomic commit+tag operations to prevent race conditions
- Rollback warnings when GitHub release creation fails after npm publish

### Changed
- GitHub Actions release workflow now fully automated with zero manual editing required
- CHANGELOG structure updated to comply with Keep-a-Changelog specification
- Replaced deprecated actions/create-release@v1 with softprops/action-gh-release@v2
- Release workflow now enforces main-branch-only releases with validation checks
- Publish workflow extracts version-specific changelog sections for GitHub releases

### Fixed
- Corrected README.md architecture diagram to match actual flat file structure
- Removed undocumented configuration options from documentation
- Updated documentation dates to accurate values
- CHANGELOG [Unreleased] section positioning (now at top per Keep-a-Changelog spec)
- Race condition between commit and tag push operations (now atomic with --follow-tags)
- Changelog insertion logic compatibility with Keep-a-Changelog format

### Security
- Added concurrency controls to prevent simultaneous release/publish operations
- Implemented branch validation to prevent accidental releases from feature branches
- Added package verification step to validate contents before npm publish

## [1.0.0] - 2025-11-05

### Added
- Complete npm Audit Scanner Implementation
- npm Registry API Integration
- Advanced Advisory Analysis
- Production-Grade Architecture
- Comprehensive Test Suite
