# rust-doctor

A Rust-native CLI static-analysis tool inspired by [react-doctor](https://github.com/astahmer/react-doctor). It scans Rust workspaces for idioms, design patterns, anti-patterns, code-organization issues, and toolchain warnings — producing output that is readable for humans and easily consumed by LLM agents.

---

## Table of Contents

- [Installation](#installation)
- [Build](#build)
- [Usage](#usage)
  - [Basic Scan](#basic-scan)
  - [Filtering](#filtering)
  - [Output Formats](#output-formats)
- [Configuration](#configuration)
- [Health Score](#health-score)
- [Rule Philosophy](#rule-philosophy)
- [MVP Rule List](#mvp-rule-list)
- [Phase-2 Deferred Rules](#phase-2-deferred-rules)
- [JSON / SARIF Output](#json--sarif-output)
- [Verification](#verification)

---

## Installation

```bash
cargo install --path .
```

Or clone and build locally:

```bash
git clone https://github.com/example/rust-doctor
cd rust-doctor
cargo build --release
```

The binary is placed at `target/release/rust-doctor`.

---

## Build

```bash
cargo build            # debug
cargo build --release  # release
cargo test             # run tests
```

---

## Usage

### Basic Scan

```bash
# Scan the current workspace
rust-doctor

# Scan a specific directory
rust-doctor ./my-crate
```

### Filtering

```bash
# Show only Anti-Pattern findings
rust-doctor --category anti-pattern

# Show findings at WARNING severity or above
rust-doctor --severity warning

# Fail with exit code 1 if any ERROR-level findings exist
rust-doctor --fail-on error

# Skip cargo check / clippy toolchain analysis
rust-doctor --no-toolchain
```

### Output Formats

```bash
# Human-readable (default)
rust-doctor --format human

# JSON (matches the Report/Finding data model)
rust-doctor --format json

# SARIF 2.1.0 (CI / IDE integration)
rust-doctor --format sarif
```

---

## Configuration

rust-doctor reads an optional TOML config file passed via `--config`:

```toml
# .rust-doctor.toml

[scan]
include_toolchain = true    # run cargo check
include_clippy = true       # run cargo clippy
# fail_on = "warning"       # exit 1 at or above this severity

[rules]
disabled = ["pattern.small-crates"]   # skip specific rules
warn = ["anti.deny-warnings"]         # upgrade severity for specific rules
info = []                             # downgrade severity for specific rules
```


## Health Score

rust-doctor prints a React Doctor-style health score in human output and includes the same data in JSON under `summary.health`.

The score starts at `100` and deducts points by severity and confidence:

| Finding | High confidence | Medium confidence | Low confidence |
|---------|-----------------|-------------------|----------------|
| Error | -30 | -24 | -18 |
| Warning | -10 | -8 | -6 |
| Info | -3 | -2 | -1 |

Grades are intentionally simple: `A` = 90-100, `B` = 75-89, `C` = 60-74, `D` = 40-59, and `F` = 0-39. The score is a quick triage signal, not a replacement for reading findings.

---
---

## Rule Philosophy

Every rule in rust-doctor is derived from the [Rust unofficial patterns](https://rust-unofficial.github.io/patterns/) catalog and follows these principles:

- **Stable rule IDs**: Every rule has a unique, dot-separated identifier (`category.rule-name`) that never changes between versions. This enables tooling (CI, IDEs, LLM agents) to reference rules reliably.
- **Severity + Confidence**: Each finding carries a `Severity` (error / warning / info) and a `Confidence` (high / medium / low). Many pattern/idiom checks are "info" because they express trade-offs, not absolute errors.
- **Human + LLM output**: Every finding includes:
  - `message` — what was found.
  - `why_it_matters` — the rationale.
  - `suggestion` — concrete remediation.
  - `llm_fix_prompt` — a prompt an LLM agent can use to fix the issue.
  - `references` — links to external documentation.
- **Category grouping**: Output is grouped by category (Anti-Pattern, Idiom, Organization, Pattern, Toolchain) then sorted by severity within each category.
- **Trade-off aware**: Rust patterns are rarely black-and-white. rust-doctor flags potential issues but reports many as guidance (info severity) with confidence labels.

---

## MVP Rule List

The following rules are implemented in the current release:

| Rule ID | Title | Category | Severity | Confidence |
|---------|-------|----------|----------|------------|
| `anti.deny-warnings` | Deny-warnings suppresses future lints | Anti-Pattern | Warning | High |
| `anti.deref-polymorphism` | Suspicious Deref implementation | Anti-Pattern | Warning | Medium |
| `idiom.borrowed-args` | Use borrowed types for arguments | Idiom | Info | High |
| `idiom.default-trait` | Consider implementing Default | Idiom | Info | Medium |
| `idiom.option-iteration` | Avoid for loops over Option | Idiom | Info | Medium |
| `idiom.privacy-extensibility` | Consider #[non_exhaustive] for public types | Idiom | Info | Low |
| `pattern.builder` | Consider builder pattern | Pattern | Info | Medium |
| `pattern.contain-unsafety` | Consider containing unsafe code | Organization | Info | Low |
| `pattern.custom-traits-for-bounds` | Consider custom trait for complex bounds | Pattern | Info | Low |
| `pattern.small-crates` | Consider splitting large crates | Organization | Info | Low |

---

## Phase-2 Deferred Rules

These rules are registered but inert (emit no findings) until type/flow analysis infrastructure is available:

| Rule ID | Title | Category | Severity |
|---------|-------|----------|----------|
| `anti.clone-to-satisfy-borrow-checker` | Clone to satisfy borrow checker | Anti-Pattern | Warning |
| `ffi.idiomatic-errors` | FFI idiomatic errors | Toolchain | Warning |
| `pattern.newtype` | Consider newtype for type safety | Pattern | Info |

Future phases will add rules for: FFI string handling, RAII guards, compose structs, coercion arguments, mem::take/replace, temp mutability, return-consumed-arg-on-error, and more.

---

## JSON / SARIF Output

### JSON Schema

The `--format json` output is a JSON serialization of the `Report` model:

```json
{
  "tool_version": "0.1.0",
  "workspace_root": "/path/to/workspace",
  "summary": {
    "total": 2,
    "errors": 0,
    "warnings": 1,
    "infos": 1,
    "health": {
      "score": 88,
      "grade": "B",
      "label": "Good",
      "deductions": 12
    }
  },
  "findings": [
    {
      "rule_id": "anti.deny-warnings",
      "title": "Deny-warnings suppresses future lints",
      "category": "anti-pattern",
      "severity": "warning",
      "confidence": "high",
      "message": "Package \"my-crate\" uses `#![deny(warnings)]` which suppresses future lints",
      "why_it_matters": "Denying all warnings opts out of Rust stability guarantees…",
      "suggestion": "Use `RUSTFLAGS=-D warnings` in CI instead…",
      "references": ["https://rust-unofficial.github.io/patterns/anti-patterns/deny-warnings.html"],
      "llm_fix_prompt": "Remove `#![deny(warnings)]` from the crate root. Instead, use `RUSTFLAGS=-D warnings` in CI or explicitly deny specific lint names.",
      "location": {
        "path": "src/main.rs",
        "line": 1,
        "column": null,
        "end_line": 1,
        "end_column": null
      }
    }
  ]
}
```

### SARIF 2.1.0

The `--format sarif` output conforms to the SARIF 2.1.0 specification:

```json
{
  "version": "2.1.0",
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "rust-doctor",
          "version": "0.1.0"
        }
      },
      "results": [
        {
          "ruleId": "anti.deny-warnings",
          "level": "warning",
          "message": { "text": "Package \"my-crate\" uses `#![deny(warnings)]` …" },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "src/main.rs" },
                "region": { "startLine": 1, "startColumn": 1 }
              }
            }
          ],
          "help": { "text": "Remove `#![deny(warnings)]` from the crate root…" }
        }
      ]
    }
  ]
}
```

SARIF output includes `ruleId`, `level` (mapped from severity), `message`, `locations` (with `artifactLocation.uri` and `region`), and `help` text from the rule's LLM fix prompt.

---

## Verification

To verify the tool is working correctly:

```bash
# 1. Build
cargo build --release

# 2. Run human-readable output on the repo itself
./target/release/rust-doctor --path . --format human

# 3. Run JSON output
./target/release/rust-doctor --path . --format json

# 4. Run SARIF output
./target/release/rust-doctor --path . --format sarif

# 5. Run tests
cargo test

# 6. Verify a specific category filter
./target/release/rust-doctor --path . --category anti-pattern --format human

# 7. Verify severity filter
./target/release/rust-doctor --path . --severity warning --format human
```

All three formats should produce consistent findings. The JSON output should be valid JSON that round-trips through `serde_json`, and the SARIF output should validate against the SARIF 2.1.0 schema.

---

*rust-doctor is released under the MIT license. Rule references are based on the Rust unofficial patterns project (MPL-2.0).*
