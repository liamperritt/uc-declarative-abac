# UC ABAC Governor — Development Guide

## Project overview

A Python framework that lets Databricks customers define ABAC governance (tags, grants, masking, filtering, UC objects) as declarative YAML configs. The engine reads configs, queries UC system tables for current state, computes diffs, and applies only the required changes.

See `README.md` for the full design specification, YAML config structures, and examples.

## Architecture

### Two config namespaces

- **`definitions:`** — catalog-agnostic, reusable templates (schemas, tables, volumes, functions, policies). These are never deployed directly; they are referenced by resources.
- **`resources:`** — concrete, deployable instances (governed_tags, catalogs, and promoted definitions with a fixed catalog/schema).

### Core engine pipeline

1. **Discovery** — recursively find all YAML files (directory structure is convention, not enforced)
2. **Parsing** — load all `definitions:` and `resources:` blocks, build a registry keyed by definition ID
3. **Resolution** — resolve all `$ref: $defs/<type>/<key>` entries, apply overrides (fields on a `$ref` entry override the definition), support recursive `$ref` nesting
4. **State query** — read current UC state from system tables (information_schema, system.access, etc.)
5. **Diff computation** — compare desired state (resolved configs) against actual state (system tables)
6. **Apply** — execute only the SQL/API calls needed to reconcile the diff

### Deployment semantics

- **UC objects & attributes** (catalogs, schemas, tables, volumes, functions, comments): additive only — create/update, never delete
- **Tags & grant policies**: additive + removals/revokes
- **Mask & filter policies**: additive only (UC limitation — no system table to track these yet)

## YAML config conventions

### Definition IDs

Keys use `|`-delimited segments by convention (e.g. `operations|sales|orders`), but the delimiter is not enforced — keys can be any valid YAML string.

### Key conventions by type

| Type | Convention | Example |
|------|-----------|---------|
| schemas | `<domain>\|<schema>` | `operations\|sales` |
| tables | `<domain>\|<schema>\|<table>` | `operations\|sales\|orders` |
| volumes | `<domain>\|<schema>\|<volume>` | `platform\|landing\|raw_events` |
| functions | `<domain>\|<schema>\|<function>` | `platform\|shared\|mask_pii_email` |
| policies | `<domain>\|<policy>` | `shared\|mask_pii_email` |

### $ref syntax

`$ref: $defs/<type>/<key>` — inspired by JSON Schema's `$defs` and `$ref` keywords. The `<type>` is one of: `schemas`, `tables`, `volumes`, `functions`, `policies`.

### Overrides

Any `$ref` entry can include additional fields that override the definition. Unspecified fields fall back to the definition. Overrides support recursive `$ref` nesting.

### `name` field

Optional on resources. If omitted, the dictionary key is used as the UC object name.

## Table definitions — security model

Two approaches to RLS/CLS, which can coexist:

1. **Directly applied functions** — `filter` (table-level) and `mask` (column-level) specify a UC function name applied directly
2. **Tag-based ABAC policies** — tag objects/columns and let policy definitions match against tags to apply masking, filtering, and grants across all matching objects

## Policy types

- **`mask`** — column masking via tags. Fields: `function`, `to`, `except`, `tags`
- **`filter`** — row filtering via tags. Fields: `function`, `to`, `except`, `tags`
- **`grant`** — privilege grants via tags. Fields: `privileges`, `to`, `tags`, `expiry_date`

Multiple tags on a policy use AND semantics — all must match.

## Code style

- Python project — use standard Python conventions
- Use `databricks-sdk` for Databricks API interactions
- Use `pyyaml` for YAML parsing
- Prefer SQL via Databricks SQL connector for UC operations (CREATE, ALTER, GRANT, etc.)
- Query UC system tables (not API) to determine current deployed state
- Keep the engine idempotent — running the same configs twice should produce no changes on the second run

## Testing

- Unit tests for YAML parsing, $ref resolution, override merging, and diff computation
- Integration tests require a Databricks workspace with Unity Catalog
- Use `pytest` as the test framework
