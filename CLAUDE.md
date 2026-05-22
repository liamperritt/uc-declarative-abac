# UC Declarative ABAC  — Development Guide

## Project overview

A Python framework that lets Databricks customers define ABAC governance (tags, grants, masking, filtering, UC objects) as declarative YAML configs. The engine reads configs, queries UC system tables for current state, computes diffs, and applies only the required changes.

See `README.md` for the full design specification, YAML config structures, and examples.

## Architecture

### Two config namespaces

- **`definitions:`** — catalog-agnostic, reusable templates (catalogs, schemas, tables, volumes, functions, policies). These are never deployed directly; they are referenced by resources.
- **`resources:`** — concrete, deployable instances (governed_tags, catalog, schemas, etc. with a fixed catalog_name/schema_name).

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

### Principal resolution

Any domain that references principals (users, groups, service principals) in its diff **must** resolve them from display-name form to identifier form before diffing. The two sides speak different dialects:

- **Desired state (from YAML config)** uses **display names** for every principal type.
- **Actual state (from UC system tables or SDK list APIs)** uses **canonical identifiers**. For users the identifier is the username, for groups it's the display name, but for service principals it's the **application_id (UUID)** — not the display name.

Comparing raw strings (or pre-resolution `Principal`s with only one side populated) would make every SP-bearing row look like a change on every run.

#### The `Principal` type

A single frozen dataclass at `src/uc_declarative_abac/principals/state.py` represents both unresolved and resolved principals. Resolution status is a runtime property, not a type:

- **Unresolved:** `principal_type == PrincipalType.UNKNOWN`, with exactly one of `name` / `identifier` truthy. Config-side has `name` set; UC-side has `identifier` set.
- **Resolved:** `principal_type` ∈ {USER, GROUP, SERVICE_PRINCIPAL}, with both `name` and `identifier` truthy. This invariant is enforced by `__post_init__`.

#### Pipeline shape

1. **Compilers** (`<domain>/compiler.py`) produce state with `Principal(principal_type=UNKNOWN, name=<from YAML>)`.
2. **Fetch helpers** (`UnityCatalogHelper.fetch_actual_*`) produce state with `Principal(principal_type=UNKNOWN, identifier=<from UC>)`. They do **not** depend on `WorkspaceHelper` — this keeps them safe inside the parallel fetch block.
3. **Differs** (`<domain>/differ.py`) own principal resolution. `compute_*_diff` accepts a `PrincipalResolver` and a `ChangeLogger`, resolves principals on both desired and actual state internally (via a private `_resolve_*` helper in the same module), and returns a fully-resolved diff. Unknown principals are logged and the affected state row is dropped.
4. **Executors** call `ensure_resolved(principal)` from `principals/resolver.py` before reading `.identifier`. This asserts the runtime invariant.

#### Key APIs (all in `src/uc_declarative_abac/principals/resolver.py`)

- `PrincipalResolver(ws_helper).resolve_principal(p)` — resolve one, raises `PrincipalValidationError` on failure.
- `PrincipalResolver(ws_helper).resolve_principals(batch)` — all-or-nothing; on any failure raises one `PrincipalValidationError` whose message lists every offender.
- `ensure_resolved(p)` / `ensure_all_resolved(iterable)` — runtime guards used at the executor boundary.

`Principal.identifier` and `.name` default to the empty string. An unresolved Principal from config has `name` truthy and `identifier` empty; an unresolved Principal from UC state is the reverse. The resolver picks its lookup direction by checking which field is truthy.

Unknown principals are collected as `ExecutionError(PrincipalValidationError)` on `ChangeLogger` and excluded from the diff; they do not abort the run.

The privileges, securables, and policies differs all follow this pattern — see the private `_resolve_*` function at the bottom of each `<domain>/differ.py`. No separate per-domain `resolver.py` modules exist.

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

## Running Python

Always use the `.venv` virtual environment when running `python`, `pip`, `pytest`, or any other Python tool — e.g. `.venv/bin/python`, `.venv/bin/pytest`.

## Code style

- Python project — use standard Python conventions
- Use `databricks-sdk` for Databricks API interactions
- Use `pyyaml` for YAML parsing
- Prefer SQL via Databricks SQL connector for UC operations (CREATE, ALTER, GRANT, etc.)
- Query UC system tables (not API) to determine current deployed state
- Keep the engine idempotent — running the same configs twice should produce no changes on the second run
- Minimise nesting and cognitive complexity — extract logic into well-named helper functions to keep top-level functions flat
- Prefer immutability — helper functions should return new values rather than modifying state passed in as arguments
- No forward references within a module — always define a function/helper *above* the function that calls it. The top-level public function(s) of a module should sit at the bottom, so a reader scrolling top-down sees primitives → helpers → entry point. Python allows forward references at runtime, but readability suffers when you have to scroll down to find a definition

## Testing

- Use `pytest` as the test framework
- Test functions are root-level functions (no test classes)
- Test naming follows BDD (Behaviour-Driven Development) convention: `test_<class_or_module>_<does_behaviour>` or `test_<class_or_module>_<does_behaviour>_when_<state>` — the prefix is the class or module name (e.g. `test_discovery_`, `test_catalog_config_`, `test_uc_helper_`), never an individual function name — functions/methods are behaviours of a class or module
- Use block comments (`# ---` separator lines) to visually group tests by the class they target within a test file when applicable
- Tests should only touch public functions and methods and should never import private ones
- Test assertions should be loose enough to test the behaviour without tightly coupling to the internals of the implementation. The implementation should be changeable without breaking the test, as long as the same behaviour and public interface are maintained.

## Implementation approach

See `docs/implementation_design.md` for the full implementation plan.

This project uses **Test-Driven Development (TDD)**/**Behaviour-Driven Development (BDD)** with a three-agent pattern. **All implementation plans must follow TDD/BDD** — when creating a new plan, structure it around the TDD/BDD cycle (stubs → tester agent → RED → implementer agent → GREEN → refactor).

### Agent roles

- **Manager agent** (you, the main Claude agent) — orchestrates the TDD cycle:
  - Scaffolds models, dataclasses, stubs, and test infrastructure (Phase 1)
  - Dispatches work to tester and implementer sub-agents
  - Runs `pytest` after each sub-agent to verify red/green status
  - Performs the **refactor** step once all tests for a module are green
  - Tracks progress and advances to the next module

- **Tester agent** (sub-agent) — writes a single test case. Give it:
  - The BDD-style test case name and description from the implementation design
  - The public API signature of the function/method under test
  - The relevant state/model dataclasses
  - The test file path and any existing fixtures from `conftest.py`
  - It must NOT write any production code

- **Implementer agent** (sub-agent) — implements just enough code to pass the failing test. Give it:
  - The failing test (file path + test name)
  - The stub file to implement in
  - The relevant models/dataclasses
  - The test output showing the failure
  - It must NOT modify tests or refactor

### TDD/BDD cycle per module

```
For each test case in the module:
  1. Spawn Tester agent → writes one test
  2. Run pytest → confirm RED (test fails against stub)
  3. Spawn Implementer agent → implements just enough to pass
  4. Run pytest → confirm GREEN (test passes)
  5. Repeat for next test case

Once all tests for the module are green:
  6. Review implementation and REFACTOR if needed
  7. Run pytest → confirm all tests still green after refactor
```

You may run tester and implementer agents in parallel for independent test cases where there are no dependencies between them.
