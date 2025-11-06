<!--
Copyright (c) 2025 maloma7. All rights reserved.
SPDX-License-Identifier: MIT
-->

<img src="docs/icons/logo.svg" width="100%" alt="Bun npm Scanner" />

# Bun npm Scanner

A production-grade security scanner for [Bun](https://bun.sh/) that integrates with npm registry's [GitHub Advisory Database](https://github.com/advisories) to detect known vulnerabilities in npm packages during installation.

[![npm version](https://img.shields.io/npm/v/@bun-security-scanner/npm?color=dc2626)](https://npmjs.com/package/@bun-security-scanner/npm)
[![npm downloads](https://img.shields.io/npm/dm/@bun-security-scanner/npm?color=dc2626)](https://npmjs.com/package/@bun-security-scanner/npm)
[![License: MIT](https://img.shields.io/badge/License-MIT-dc2626)](LICENSE)
[![Built with Claude](https://img.shields.io/badge/Built_with-Claude-dc2626?style=flat&logo=claude&logoColor=dc2626)](https://anthropic.com/claude-code)
[![Checked with Biome](https://img.shields.io/badge/Checked_with-Biome-dc2626?style=flat&logo=biome&logoColor=dc2626)](https://biomejs.dev)

## What is GitHub Advisory Database?

The [GitHub Advisory Database](https://github.com/advisories) provides security vulnerability information for open source projects. It is:

- **Authoritative**: Maintained by GitHub and the open source security community
- **Comprehensive**: Includes npm Security Advisories and other sources
- **Up-to-date**: Continuously updated with the latest security advisories
- **npm's Official Database**: The same database used by `bun audit` or `npm audit`

## Why Use This Scanner?

**Alternative Trust Model**: Unlike other scanners that rely on Google's OSV.dev database, this scanner uses npm registry's official vulnerability database powered by GitHub's Advisory Database. This provides:

- **Direct from Source**: Queries npm registry directly (registry.npmjs.org)
- **Microsoft/GitHub Infrastructure**: Data sovereignty with Microsoft/GitHub instead of Google
- **Official npm Data**: Uses the same backend as `npm audit` and `bun audit`
- **Native Integration**: Leverages Bun's built-in gzip compression and performance features

## Features

- **Real-time Scanning**: Checks packages against npm registry during installation
- **GitHub Advisory Database**: Uses npm's official vulnerability database
- **High Performance**: Efficient bulk queries with gzip compression
- **Fail-safe**: Never blocks installations due to scanner errors
- **Structured Logging**: Configurable logging levels with contextual information
- **Precise Matching**: Accurate vulnerability-to-package version matching using semver
- **Configurable**: Environment variable configuration for all settings
- **Zero Dependencies**: Only uses Bun's built-in features and Zod for validation

## Installation

**No API keys or registration required** - completely free to use with zero setup beyond installation.

```bash
# Install as a dev dependency
bun add -d @bun-security-scanner/npm
```

## Configuration

### 1. Enable the Scanner

Add to your `bunfig.toml`:

```toml
[install.security]
scanner = "@bun-security-scanner/npm"
```

### 2. Optional: Configuration Options

The scanner can be configured via environment variables:

```bash
# Logging level (debug, info, warn, error)
export NPM_SCANNER_LOG_LEVEL=info

# Custom npm registry URL (optional)
export NPM_SCANNER_REGISTRY_URL=https://registry.npmjs.org

# Request timeout in milliseconds (default: 30000)
export NPM_SCANNER_TIMEOUT_MS=30000
```

## How It Works

### Security Scanning Process

1. **Package Detection**: Bun provides package information during installation
2. **Smart Deduplication**: Eliminates duplicate package@version queries
3. **Bulk Query**: Uses npm registry's `/npm/v1/security/advisories/bulk` endpoint
4. **Gzip Compression**: Compresses request payload for optimal performance
5. **Version Matching**: Uses Bun's semver to match vulnerable version ranges
6. **Advisory Generation**: Creates actionable security advisories

### Advisory Levels

The scanner generates two types of security advisories based on npm severity levels:

#### Fatal (Installation Blocked)
- **Severity**: `critical` or `high`
- **Action**: Installation is immediately blocked
- **Examples**: Remote code execution, privilege escalation, data exposure

#### Warning (User Prompted)
- **Severity**: `moderate`, `low`, or `info`
- **Action**: User is prompted to continue or cancel
- **TTY**: Interactive choice presented
- **Non-TTY**: Installation automatically cancelled
- **Examples**: Denial of service, information disclosure, deprecation warnings

### Error Handling Philosophy

The scanner follows a **fail-safe** approach:
- Network errors don't block installations
- Malformed responses are logged but don't halt the process
- Scanner crashes return empty advisory arrays (allows installation)
- Only genuine security threats should prevent package installation

## Usage Examples

### Basic Usage

```bash
# Scanner runs automatically during installation
bun install express
# -> Checks express and all dependencies for vulnerabilities

bun add lodash@4.17.20
# -> May warn about known lodash vulnerabilities in older versions
```

### Development Usage

```bash
# Enable debug logging to see detailed scanning information
NPM_SCANNER_LOG_LEVEL=debug bun install

# Test with a known vulnerable package
bun add event-stream@3.3.6
# -> Should trigger security advisory
```

### Configuration Examples

```bash
# Increase timeout for slow networks
NPM_SCANNER_TIMEOUT_MS=60000 bun install

# Use custom registry (advanced)
NPM_SCANNER_REGISTRY_URL=https://registry.custom.com bun install
```

## Architecture

The scanner is built with a modular, production-ready architecture:

```
src/
├── index.ts              # Main scanner implementation
├── client.ts             # npm registry API client with gzip support
├── processor.ts          # Advisory processing and Bun advisory generation
├── cli.ts                # CLI interface for testing
├── schema.ts             # Zod schemas for npm audit API responses
├── constants.ts          # Centralized configuration management
├── logger.ts             # Structured logging with configurable levels
├── retry.ts              # Robust retry logic with exponential backoff
├── severity.ts           # npm severity mapping and assessment
└── types.ts              # TypeScript type definitions
```

### Key Design Principles

1. **Separation of Concerns**: Each module has a single, well-defined responsibility
2. **Error Isolation**: Failures in one component don't cascade to others
3. **Performance Optimization**: Bulk processing, deduplication, and gzip compression
4. **Observability**: Comprehensive logging for debugging and monitoring
5. **Type Safety**: Full TypeScript coverage with runtime validation

## Comparison with Other Scanners

| Feature | bun-npm-scanner | bun-osv-scanner |
|---------|------------------|-----------------|
| **Database** | npm/GitHub Advisory | Google OSV.dev |
| **Provider** | Microsoft/GitHub | Google |
| **Compression** | Native gzip | None |
| **API Calls** | Single bulk request | Batch + individual details |
| **Ecosystem** | npm-focused | Multi-ecosystem |
| **Trust Model** | npm official source | Aggregated sources |

## Testing

```bash
# Run the test suite
bun test

# Run with coverage
bun test --coverage

# Type checking
bun run typecheck

# Linting
bun run lint
```

## Development

### Building from Source

```bash
git clone https://github.com/bun-security-scanner/npm.git
cd npm
bun install
bun run build
```

### Contributing

We do not accept pull requests as this package is actively maintained. However, we appreciate if developers report bugs or suggest features by [opening an issue](https://github.com/bun-security-scanner/npm/issues/new).

## API Reference

### npm Audit Integration

This scanner integrates with the npm registry bulk advisory endpoint:

- **POST /-/npm/v1/security/advisories/bulk**: Bulk advisory queries with gzip compression

Request format:
```json
{
  "package-name": ["1.0.0", "2.0.0"],
  "another-package": ["3.0.0"]
}
```

Response format:
```json
{
  "advisory-id": {
    "id": "GHSA-xxxx-xxxx-xxxx",
    "title": "Vulnerability title",
    "name": "package-name",
    "severity": "high",
    "vulnerable_versions": ">=1.0.0 <2.0.0",
    "url": "https://github.com/advisories/GHSA-xxxx-xxxx-xxxx",
    "overview": "Detailed description..."
  }
}
```

### Configuration Reference

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `NPM_SCANNER_LOG_LEVEL` | `info` | Logging level: debug, info, warn, error |
| `NPM_SCANNER_REGISTRY_URL` | `https://registry.npmjs.org` | npm registry base URL |
| `NPM_SCANNER_TIMEOUT_MS` | `30000` | Request timeout in milliseconds |

## Troubleshooting

### Common Issues

**Scanner not running during installation?**
- Verify `bunfig.toml` configuration
- Check that the package is installed as a dev dependency
- Enable debug logging: `NPM_SCANNER_LOG_LEVEL=debug bun install`

**Network timeouts?**
- Increase timeout: `NPM_SCANNER_TIMEOUT_MS=60000`
- Check internet connectivity to registry.npmjs.org
- Consider corporate firewall restrictions

**Too many false positives?**
- npm Advisory Database data is authoritative - verify vulnerabilities manually
- Check if you're using an outdated package version
- Report false positives to GitHub Security Advisories

### Debug Mode

Enable comprehensive debug output:

```bash
NPM_SCANNER_LOG_LEVEL=debug bun install your-package
```

This shows:
- Package deduplication statistics
- API request/response details
- Advisory matching decisions
- Performance timing information

## License

MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- **GitHub Advisory Database**: For maintaining the comprehensive vulnerability database
- **npm Team**: For the robust advisory infrastructure
- **Bun Team**: For the innovative Security Scanner API

## Related Projects

- [Bun Security Scanner API](https://bun.com/docs/install/security-scanner-api)
- [GitHub Advisory Database](https://github.com/advisories)
- [bun-osv-scanner](https://github.com/bun-security-scanner/osv) - Alternative scanner using Google's OSV.dev

---

**Last Updated**: November 5, 2025
**Version**: 1.0.0

*This scanner provides an alternative trust model for developers who prefer to use npm's official advisory database powered by GitHub.*
