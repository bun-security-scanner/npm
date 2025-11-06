# Test Fixtures

This directory contains test data used across the test suite.

## Files

### `sample-changelog.md`
- Valid CHANGELOG.md following Keep-a-Changelog specification
- Used for testing changelog parsing and validation
- Contains realistic version history

### `malformed-changelog.md`
- Intentionally malformed CHANGELOG for error testing
- Tests edge cases and error handling
- Includes common mistakes (wrong version order, missing brackets, etc.)

### `sample-commits.json`
- Collection of commit messages for testing conventional commits parsing
- Includes:
  - Conventional commits (feat, fix, docs, refactor, etc.)
  - Non-conventional commits
  - Multi-line commits with breaking changes
  - Edge cases (unicode, special characters, long messages)

### `sample-package.json`
- Example package.json with realistic configuration
- Used for testing package validation logic
- Represents actual @bun-security-scanner/npm package structure

## Usage

Import fixtures in tests:

```typescript
import { readFile } from "fs/promises";
import { join } from "path";

const changelog = await readFile(
  join(import.meta.dir, "../fixtures/sample-changelog.md"),
  "utf-8"
);
```

Or use Bun's file API:

```typescript
const file = Bun.file("tests/fixtures/sample-changelog.md");
const changelog = await file.text();
```
