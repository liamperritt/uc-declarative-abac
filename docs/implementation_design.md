# MVP Implementation Design — UC ABAC Governor

## Context

This is a greenfield Python project (no code exists yet, only README.md and CLAUDE.md). The goal is to build an MVP of the declarative ABAC governance engine described in the README. The MVP scope is intentionally narrow:

- **In scope:** YAML discovery/parsing, `$ref` resolution with overrides, catalog/schema/table/volume tagging (set + unset), grant policy computation + execution (grant + revoke)
- **Out of scope:** Object creation/updates, comments, owners, RFA, filters, masks, functions, governed tags, column tags, expiry_date on grants

The engine reads YAML configs, queries Unity Catalog system tables for current state, computes a diff, and applies only the required changes.

### Domain separation

Tags and privileges are two **independent domains** with their own compilers, diffs, and executors. They share common infrastructure (config parsing, `$ref` resolution, helpers) but can be run independently. The governor orchestrates both, but neither domain knows about the other.

---

## Methodology: Test-Driven Development (TDD)

The implementation follows a strict red-green-refactor cycle using a **three-agent pattern**:

### Agent roles

1. **Manager agent** (main Claude agent) — orchestrates the TDD cycle. Responsible for:
   - Scaffolding (Phase 1): models, dataclasses, stubs, and test infrastructure
   - Dispatching work to the tester and implementer agents
   - Running `pytest` after each agent completes to verify red/green status
   - Performing the **refactor** step once all tests for a module are green
   - Tracking progress and moving to the next module

2. **Tester agent** (sub-agent) — writes a single test case. Receives:
   - The test case name and description from this plan
   - The public API signature of the function/method under test
   - The relevant state/model dataclasses
   - The path to the test file
   - Any existing test fixtures from `conftest.py`

   The tester writes the test and returns. It does **not** implement any production code.

3. **Implementer agent** (sub-agent) — implements just enough production code to make the failing test pass. Receives:
   - The failing test (file path + test name)
   - The stub file to implement in
   - The relevant models/dataclasses
   - The test output showing the failure

   The implementer writes the minimum code to pass the test and returns. It does **not** modify tests or refactor.

### TDD cycle per module

```
For each test case in the module:
  1. Manager spawns Tester agent → writes one test
  2. Manager runs pytest → confirms RED (test fails against stub)
  3. Manager spawns Implementer agent → implements just enough to pass
  4. Manager runs pytest → confirms GREEN (test passes)
  5. Repeat for next test case

Once all tests for the module are green:
  6. Manager reviews the implementation and performs REFACTOR if needed
  7. Manager runs pytest → confirms all tests still green after refactor
```

### Refactoring objectives

When refactoring, prioritise:
- **Minimise nesting and cognitive complexity** — extract logic into well-named helper functions to keep top-level functions flat
- **Prefer immutability** — helper functions should return new values rather than modifying state passed in as arguments

The manager may run the tester and implementer for independent test cases in parallel where there are no dependencies between them (e.g., multiple simple differ tests).

### Test conventions

Tests are the functional requirements. They:
- Only test **public methods/functions** — never assert on private internals
- **Root-level functions only** — no test classes
- Use **BDD-style names**: `test_<class_or_module>_<does_behaviour>` or `test_<class_or_module>_<does_behaviour>_when_<state>` — the prefix is the class or module name (e.g. `test_discovery_`, `test_config_file_`, `test_uc_helper_`), never an individual function name — functions/methods are behaviours of a class or module
- **Do not couple to SQL syntax** — use `sqlglot` to parse generated SQL and assert on structural components (table names, column refs, statement type, clauses) rather than exact string matches
- **Do not couple to internal structure** — assert on inputs and outputs of public interfaces, not how the code is organised internally

---

## Project Structure

```
uc-abac-governor/
├── pyproject.toml
├── src/
│   └── uc_abac_governor/
│       ├── __init__.py
│       ├── __main__.py                # CLI entry point
│       ├── governor.py                # Top-level orchestrator
│       │
│       │── models.py                  # Pydantic config models (shared)
│       │── types.py                   # Shared enums (SecurableType) + custom exceptions
│       │── discovery.py               # YAML file discovery + raw loading (shared)
│       │── resolver.py                # $ref resolution + override merging (shared)
│       │
│       │── helpers/
│       │   ├── __init__.py
│       │   ├── unity_catalog.py       # UnityCatalogHelper (WorkspaceClient wrapper)
│       │   └── account.py             # AccountHelper (AccountClient wrapper)
│       │
│       ├── tags/                      # Tags domain
│       │   ├── __init__.py
│       │   ├── state.py               # SecurableTag dataclass + TagDiff
│       │   ├── compiler.py            # Resolved config → desired tags
│       │   ├── differ.py              # Set-based tag diff
│       │   └── executor.py            # ALTER ... SET/UNSET TAGS SQL
│       │
│       └── privileges/                # Privileges domain
│           ├── __init__.py
│           ├── state.py               # SecurablePrivilege dataclass + PrivilegeDiff
│           ├── compiler.py            # Resolved config + tag matching → desired privileges
│           ├── differ.py              # Set-based privilege diff
│           └── executor.py            # GRANT/REVOKE SQL
│
└── tests/
    ├── __init__.py
    ├── conftest.py                    # Shared mocks + fixtures
    ├── test_models.py
    ├── test_discovery.py
    ├── test_resolver.py
    ├── test_unity_catalog.py
    ├── test_account.py
    ├── tags/
    │   ├── __init__.py
    │   ├── test_compiler.py
    │   ├── test_differ.py
    │   └── test_executor.py
    ├── privileges/
    │   ├── __init__.py
    │   ├── test_compiler.py
    │   ├── test_differ.py
    │   └── test_executor.py
    └── test_governor.py
```

---

## Dependencies (`pyproject.toml`)

Runtime:
- `pydantic` — config model validation
- `pyyaml` — YAML parsing
- `databricks-sdk` — WorkspaceClient (SQL Statement Execution API) + AccountClient (principals)

Dev:
- `pytest` — test framework
- `sqlglot` — SQL parsing for structural assertions in tests
- `ruff` — linting

---

## Phase 1: Scaffolding (no behaviour)

### Step 1: Project scaffolding

Create `pyproject.toml`, `src/uc_abac_governor/__init__.py`, all `__init__.py` files, `tests/__init__.py`.

### Step 2: `models.py` — Pydantic config models (shared)

These models represent the **fully resolved** config. All `$ref` resolution and override merging happens on raw dicts *before* Pydantic ever sees the data. By the time `ConfigFile.model_validate()` is called, every `$ref` has been replaced with the concrete definition (plus overrides applied), and the `definitions:` block has been stripped — only `resources:` remains. The Pydantic models therefore have no concept of `$ref`, `$defs`, or `definitions:`.

```python
class SecurableConfig(BaseModel):
    """Base model for all UC securable configs. Not intended to be instantiated directly."""
    name: str | None = None
    tags: dict[str, str | None] | None = None

class ColumnConfig(BaseModel):
    name: str
    tags: dict[str, str | None] | None = None

class VolumeConfig(SecurableConfig):
    pass

class TableConfig(SecurableConfig):
    columns: list[ColumnConfig] | None = None

class SchemaConfig(SecurableConfig):
    tables: list[TableConfig] | None = None
    volumes: list[VolumeConfig] | None = None

class GrantPolicyConfig(BaseModel):
    name: str | None = None
    type: Literal["grant"]
    privileges: list[str]
    to: list[str]
    tags: dict[str, str | None]

class CatalogConfig(SecurableConfig):
    policies: list[GrantPolicyConfig] | None = None
    schemas: list[SchemaConfig] | None = None

class ConfigFile(BaseModel):
    catalogs: dict[str, CatalogConfig]
```

`SecurableConfig` is a plain `BaseModel` base class (not `ABC` — Pydantic's `ABC` mixin doesn't enforce abstractness and adds no value). It provides the shared fields (`name`, `tags`) inherited by `CatalogConfig`, `SchemaConfig`, `TableConfig`, and `VolumeConfig`. `ColumnConfig` and `GrantPolicyConfig` do not extend `SecurableConfig` — columns are not standalone securables, and policies have a different shape.

Note: `GrantPolicyConfig` is the only policy type in the MVP. Mask/filter policies will be added as separate models later — for now, any non-grant policy in the raw YAML is dropped during resolution before Pydantic validation.

### Step 3: `types.py` — Shared types and exceptions

```python
class SecurableType(str, Enum):
    CATALOG = "CATALOG"
    SCHEMA = "SCHEMA"
    TABLE = "TABLE"
    VOLUME = "VOLUME"

class GovernorError(Exception):
    """Base exception for all governor errors."""

class ResolutionError(GovernorError):
    """Raised when a $ref cannot be resolved (missing key, circular ref, etc.)."""

class DuplicateKeyError(GovernorError):
    """Raised when duplicate definition keys are found across YAML files."""

class PrincipalValidationError(GovernorError):
    """Raised when one or more principal names cannot be found in the account."""

class DuplicateServicePrincipalError(GovernorError):
    """Raised when two service principals share the same display name."""
```

`SecurableType` lives here so neither domain imports from the other. All custom exceptions inherit from `GovernorError` to allow catching any governor error generically.

### Step 4: `tags/state.py` — Tags domain dataclasses

```python
@dataclass(frozen=True)
class SecurableTag:
    securable_type: SecurableType
    securable_full_name: str   # e.g. "catalog.schema.table"
    tag_name: str
    tag_value: str | None      # None = valueless tag

@dataclass
class TagDiff:
    to_add: set[SecurableTag]      # new tag key on a securable (not present in actual)
    to_update: set[SecurableTag]   # tag key exists but value changed (desired value shown)
    to_remove: set[SecurableTag]   # tag key present in actual but not in desired
```

The three categories are computed by comparing on `(securable_type, securable_full_name, tag_name)`:
- **to_add** — tag key not present on the securable in actual state
- **to_update** — tag key present on the securable in both, but `tag_value` differs
- **to_remove** — tag key present in actual but absent from desired

All three produce `ALTER ... SET TAGS` / `UNSET TAGS` SQL (the execution is identical for `to_add` and `to_update`), but the distinction enables clearer logging:
```
[ADD]    catalog.schema.table  env=prod
[UPDATE] catalog.schema.table  classification: internal → confidential
[REMOVE] catalog.schema.table  deprecated
```

### Step 5: `privileges/state.py` — Privileges domain dataclasses

```python
@dataclass(frozen=True)
class SecurablePrivilege:
    securable_type: SecurableType  # imported from types.py
    securable_full_name: str
    principal: str
    privilege_type: str            # uppercase: SELECT, MODIFY, etc.

@dataclass
class PrivilegeDiff:
    to_grant: set[SecurablePrivilege]   # desired - actual
    to_revoke: set[SecurablePrivilege]  # actual - desired
```

### Step 6: Stub all modules

Create every module file with public function/method signatures that raise `NotImplementedError`. This defines the full public API before any tests are written.

**Shared infrastructure:**

**`discovery.py`:**
- `discover_yaml_files(root: Path) -> list[Path]`
- `load_raw_configs(paths: list[Path]) -> tuple[dict, dict]`

**`resolver.py`:**
- `resolve_refs(definitions: dict, resources: dict) -> dict` — resolves all `$ref` entries in the resources dict using the definitions registry, applies overrides, strips the `definitions:` wrapper, and returns a flat dict ready for `ConfigFile.model_validate()` (i.e. `{"catalogs": {...}}`)

**`helpers/unity_catalog.py` — `UnityCatalogHelper`:**
- `__init__(self, workspace_client: WorkspaceClient, warehouse_id: str)`
- `fetch_actual_tags(self, catalog_names: list[str]) -> set[SecurableTag]`
- `fetch_actual_privileges(self, catalog_names: list[str]) -> set[SecurablePrivilege]`
- `execute_sql(self, statement: str) -> None`

**`helpers/account.py` — `AccountHelper`:**
- `__init__(self, account_client: AccountClient)`
- `fetch_principals(self) -> None`
- `validate_principal(self, name: str) -> bool`
- `validate_principals(self, names: list[str]) -> None`
- `get_sp_application_id(self, display_name: str) -> str` — returns the `application_id` for a service principal given its display name (needed for GRANT SQL which requires the SP application ID)

**Tags domain:**

**`tags/compiler.py`:**
- `compile_desired_tags(config: ConfigFile) -> set[SecurableTag]`

**`tags/differ.py`:**
- `compute_tag_diff(desired: set[SecurableTag], actual: set[SecurableTag]) -> TagDiff`

**`tags/executor.py`:**
- `execute_tag_diff(uc_helper: UnityCatalogHelper, diff: TagDiff) -> list[str]`

**Privileges domain:**

**`privileges/compiler.py`:**
- `compile_desired_privileges(config: ConfigFile, desired_tags: set[SecurableTag]) -> set[SecurablePrivilege]`
  - Takes `desired_tags` as input so it can match grant policies against the tag state without reaching into the tags domain's internals

**`privileges/differ.py`:**
- `compute_privilege_diff(desired: set[SecurablePrivilege], actual: set[SecurablePrivilege]) -> PrivilegeDiff`

**`privileges/executor.py`:**
- `execute_privilege_diff(uc_helper: UnityCatalogHelper, acct_helper: AccountHelper, diff: PrivilegeDiff) -> list[str]`
  - Takes `acct_helper` to resolve SP display names → application IDs when generating GRANT/REVOKE SQL

**Shared utility (in `governor.py` or a small helper):**
- `extract_principals(privileges: set[SecurablePrivilege]) -> list[str]` — extracts the unique principal names from a set of desired privileges for validation

**Orchestrator:**

**`governor.py`:**
- `run(config_dir: Path, workspace_client, account_client, warehouse_id: str, dry_run: bool = False) -> tuple[TagDiff, PrivilegeDiff]`

### Step 7: `conftest.py` — Shared test infrastructure

Build reusable mocks and fixtures:

- **`mock_workspace_client`** — patches `WorkspaceClient` with a mock `statement_execution.execute_statement()` that captures SQL calls and returns configurable fake results
- **`mock_account_client`** — patches `AccountClient` with mock `.users.list()`, `.groups.list()`, `.service_principals.list()` returning configurable fake principals (SPs include `application_id`)
- **`tmp_yaml_dir`** — helper to write YAML strings to a temp directory for discovery tests
- **`sample_definitions`** / **`sample_resources`** — reusable raw dict fixtures representing common test configs

---

## Phase 2: TDD Cycles (module by module)

For each module: write test → run (red) → implement → run (green) → next test.

### Module 0: `models.py` + `resolver.py` → Pydantic validation

#### Test cases (`test_models.py`):

1. **`test_config_file_validates_valid_config`** — a well-formed resolved dict passes `ConfigFile.model_validate()` without errors
2. **`test_config_file_rejects_missing_catalogs`** — a dict with no `catalogs` key raises a validation error
3. **`test_grant_policy_config_rejects_missing_privileges`** — a grant policy without `privileges` raises a validation error
4. **`test_grant_policy_config_rejects_missing_to`** — a grant policy without `to` raises a validation error
5. **`test_securable_config_allows_optional_fields`** — a catalog with only `name` and no `tags`, `schemas`, or `policies` validates successfully
6. **`test_resolve_refs_output_passes_pydantic_validation`** — an end-to-end test: raw definitions + resources with `$ref` entries are resolved and the output passes `ConfigFile.model_validate()`

### Module 1: `discovery.py`

#### Test cases (`test_discovery.py`):

1. **`test_discover_yaml_files_finds_yaml_and_yml`** — given a directory with `.yaml`, `.yml`, and `.txt` files, returns only YAML files
2. **`test_discover_yaml_files_finds_files_in_nested_directories`** — given nested subdirectories, recursively discovers all YAML files
3. **`test_discover_yaml_files_returns_empty_given_no_yaml_files`** — given a directory with no YAML files, returns an empty list
4. **`test_load_raw_configs_merges_definitions_across_files`** — given two files each contributing different definition types (schemas in one, tables in another), merges into a single definitions dict
5. **`test_load_raw_configs_merges_resources_across_files`** — given two files with different catalog resources, merges into a single resources dict
6. **`test_load_raw_configs_raises_on_duplicate_definition_key`** — given two files defining the same definition key (e.g. same schema ID), raises an error
7. **`test_load_raw_configs_ignores_files_with_no_definitions_or_resources`** — given a YAML file with unrelated content, it is silently skipped

### Module 2: `resolver.py`

#### Test cases (`test_resolver.py`):

1. **`test_resolve_refs_resolves_single_ref`** — a resource with `$ref: $defs/schemas/ops|sales` is replaced with the full definition content
2. **`test_resolve_refs_applies_override_on_ref`** — a `$ref` entry with a sibling `name` field overrides the definition's `name`
3. **`test_resolve_refs_override_replaces_entirely`** — overriding `tags` replaces the full tags dict, not a deep merge
4. **`test_resolve_refs_resolves_nested_refs`** — a schema ref contains table refs in its `tables` list; all are resolved recursively
5. **`test_resolve_refs_raises_on_missing_ref`** — a `$ref` pointing to a non-existent definition key raises an error with the bad key in the message
6. **`test_resolve_refs_passes_through_inline_entries`** — entries without `$ref` are left unchanged
7. **`test_resolve_refs_handles_mixed_refs_and_inline`** — a list containing both `$ref` entries and inline dicts resolves only the refs

### Module 3: `tags/compiler.py`

#### Test cases (`tests/tags/test_compiler.py`):

1. **`test_tag_compiler_emits_catalog_tags`** — a catalog with `tags: {env: prod}` produces `SecurableTag(CATALOG, "my_catalog", "env", "prod")`
2. **`test_tag_compiler_emits_schema_tags`** — a catalog containing a schema with tags produces `SecurableTag(SCHEMA, "catalog.schema", ...)`
3. **`test_tag_compiler_emits_table_tags`** — a table nested under a schema produces `SecurableTag(TABLE, "catalog.schema.table", ...)`
4. **`test_tag_compiler_emits_volume_tags`** — a volume nested under a schema produces `SecurableTag(VOLUME, "catalog.schema.volume", ...)`
5. **`test_tag_compiler_emits_valueless_tags`** — a tag `{operations: ~}` produces `SecurableTag(..., "operations", None)`
6. **`test_tag_compiler_emits_no_tags_when_none_defined`** — objects with no `tags` field produce no `SecurableTag` entries
7. **`test_tag_compiler_uses_dict_key_as_name_when_name_omitted`** — a catalog keyed `ops_prod` with no `name` field uses `ops_prod` as the catalog name in `securable_full_name`

### Module 4: `tags/differ.py`

#### Test cases (`tests/tags/test_differ.py`):

1. **`test_tag_differ_computes_tags_to_add`** — a desired tag whose key is not present on the securable in actual appears in `to_add`
2. **`test_tag_differ_computes_tags_to_update`** — a desired tag whose key exists on the securable in actual but with a different value appears in `to_update` (with the desired value)
3. **`test_tag_differ_computes_tags_to_remove`** — an actual tag whose key is not present in desired appears in `to_remove`
4. **`test_tag_differ_returns_empty_diff_when_in_sync`** — identical desired and actual produce an empty diff (all three sets empty)
5. **`test_tag_differ_handles_empty_desired`** — empty desired + non-empty actual produces only `to_remove`
6. **`test_tag_differ_handles_empty_actual`** — non-empty desired + empty actual produces only `to_add`
7. **`test_tag_differ_distinguishes_add_from_update`** — given a mix of new keys and changed values on the same securable, correctly separates them into `to_add` and `to_update`

### Module 5: `tags/executor.py`

Tests use `sqlglot` to parse generated SQL and assert on structural properties rather than exact SQL strings.

#### Test cases (`tests/tags/test_executor.py`):

1. **`test_tag_executor_generates_set_tags_sql_for_adds`** — given `to_add` tags, the executed SQL is a valid ALTER SET TAGS statement with the expected key-value pairs
2. **`test_tag_executor_generates_set_tags_sql_for_updates`** — given `to_update` tags, the executed SQL is a valid ALTER SET TAGS statement (same SQL as adds, but logged differently)
3. **`test_tag_executor_generates_unset_tags_sql_for_removes`** — given `to_remove` tags, the executed SQL is a valid ALTER UNSET TAGS statement
4. **`test_tag_executor_handles_valueless_tags`** — tags with `tag_value=None` produce valid SQL that sets a valueless tag
5. **`test_tag_executor_batches_tags_per_securable`** — multiple tags on the same securable are batched into a single ALTER statement
6. **`test_tag_executor_returns_all_executed_statements`** — the return value contains every SQL statement passed to `execute_sql`
7. **`test_tag_executor_executes_nothing_given_empty_diff`** — an empty `TagDiff` results in no SQL calls

### Module 6: `privileges/compiler.py`

#### Test cases (`tests/privileges/test_compiler.py`):

1. **`test_privilege_compiler_computes_privileges_from_policy`** — a grant policy with `tags: {sales: ~}` and a table tagged `{sales: ~}` produces `SecurablePrivilege` entries for each principal × privilege type
2. **`test_privilege_compiler_policy_uses_and_semantics_for_multiple_tags`** — a policy with `tags: {a: x, b: y}` only matches objects that have *both* tags
3. **`test_privilege_compiler_policy_skips_objects_without_matching_tags`** — objects that don't match the policy's tags produce no privileges
4. **`test_privilege_compiler_handles_multiple_policies_per_catalog`** — two policies on the same catalog each independently match and generate privileges
5. **`test_privilege_compiler_handles_catalog_with_no_policies`** — a catalog with no `policies` field produces no privileges
6. **`test_privilege_compiler_matches_against_desired_tags`** — the compiler uses the `desired_tags` input (not raw config tags) to determine which objects match a policy

### Module 7: `privileges/differ.py`

#### Test cases (`tests/privileges/test_differ.py`):

1. **`test_privilege_differ_computes_privileges_to_grant`** — desired privileges not in actual appear in `to_grant`
2. **`test_privilege_differ_computes_privileges_to_revoke`** — actual privileges not in desired appear in `to_revoke`
3. **`test_privilege_differ_returns_empty_diff_when_in_sync`** — identical desired and actual produce an empty diff
4. **`test_privilege_differ_handles_empty_desired`** — empty desired + non-empty actual produces only `to_revoke`
5. **`test_privilege_differ_handles_empty_actual`** — non-empty desired + empty actual produces only `to_grant`

### Module 8: `privileges/executor.py`

Tests use `sqlglot` to parse generated SQL and assert on structural properties rather than exact SQL strings.

#### Test cases (`tests/privileges/test_executor.py`):

1. **`test_privilege_executor_generates_grant_sql`** — given privileges to grant, the executed SQL is a valid GRANT statement with the expected privilege type, securable, and principal
2. **`test_privilege_executor_generates_revoke_sql`** — given privileges to revoke, the executed SQL is a valid REVOKE statement with the expected privilege type, securable, and principal
3. **`test_privilege_executor_resolves_sp_display_name_to_application_id`** — when the principal is a service principal, the executor uses `acct_helper.get_sp_application_id()` to resolve the display name to an application ID in the SQL
4. **`test_privilege_executor_returns_all_executed_statements`** — the return value contains every SQL statement passed to `execute_sql`
5. **`test_privilege_executor_executes_nothing_given_empty_diff`** — an empty `PrivilegeDiff` results in no SQL calls

### Module 9: `helpers/unity_catalog.py`

#### Test cases (`test_unity_catalog.py`):

1. **`test_uc_helper_fetch_actual_tags_returns_tags_from_query_results`** — given mock query results representing tag rows, `fetch_actual_tags` returns the correct set of `SecurableTag` dataclasses
2. **`test_uc_helper_fetch_actual_tags_returns_empty_given_no_rows`** — when the query returns no rows, returns an empty set
3. **`test_uc_helper_fetch_actual_privileges_returns_privileges_from_query_results`** — given mock query results representing privilege rows, `fetch_actual_privileges` returns the correct set of `SecurablePrivilege` dataclasses
4. **`test_uc_helper_fetch_actual_privileges_returns_empty_given_no_rows`** — when the query returns no rows, returns an empty set
5. **`test_uc_helper_execute_sql_passes_statement_to_workspace_client`** — `execute_sql` calls the workspace client's statement execution API with the given SQL
6. **`test_uc_helper_uses_external_links_disposition`** — the fetch methods use `EXTERNAL_LINKS` disposition when calling the statement execution API
7. **`test_uc_helper_queries_scoped_to_provided_catalog_names`** — the SQL passed to the API includes the provided catalog names (parsed via sqlglot to verify the WHERE/IN clause references them)
8. **`test_uc_helper_caches_tags_after_fetch`** — calling `fetch_actual_tags` twice with the same catalog names only executes the SQL query once; the second call returns the cached result
9. **`test_uc_helper_caches_privileges_after_fetch`** — calling `fetch_actual_privileges` twice with the same catalog names only executes the SQL query once; the second call returns the cached result

### Module 10: `helpers/account.py`

#### Test cases (`test_account.py`):

1. **`test_account_helper_fetch_principals_caches_users`** — after `fetch_principals`, user emails are available for validation
2. **`test_account_helper_fetch_principals_caches_groups`** — after `fetch_principals`, group display names are available for validation
3. **`test_account_helper_fetch_principals_caches_service_principals`** — after `fetch_principals`, SP display names are available for validation
4. **`test_account_helper_validate_principal_returns_true_for_known_principal`** — returns `True` for a principal that exists in the cache
5. **`test_account_helper_validate_principal_returns_false_for_unknown_principal`** — returns `False` for a name not in any cache
6. **`test_account_helper_validate_principals_raises_on_unknown_names`** — given a list with unrecognised names, raises an error listing all bad names
7. **`test_account_helper_raises_on_duplicate_service_principal_display_names`** — if two SPs have the same display name, `fetch_principals` raises an error
8. **`test_account_helper_get_sp_application_id_returns_id_for_known_sp`** — returns the `application_id` for a cached service principal display name
9. **`test_account_helper_get_sp_application_id_raises_for_unknown_sp`** — raises an error if the display name is not a known service principal

### Module 11: `governor.py` (integration-level)

#### Test cases (`test_governor.py`):

1. **`test_governor_runs_tags_workflow_end_to_end`** — given YAML configs and mock actual state with tag differences, runs the full pipeline and verifies the correct tag SQL was executed
2. **`test_governor_runs_privileges_workflow_end_to_end`** — given YAML configs with grant policies and mock actual state, verifies correct GRANT/REVOKE SQL
3. **`test_governor_produces_empty_diffs_when_in_sync`** — given configs matching the actual state, no SQL is executed
4. **`test_governor_validates_principals_before_applying`** — if a policy references an unknown principal, the run fails before any SQL is executed
5. **`test_governor_dry_run_does_not_execute_sql`** — in dry-run mode, both diffs are computed but no SQL is executed
6. **`test_governor_runs_both_domains_independently`** — tag changes and privilege changes are computed and applied via separate workflows; a failure in one does not prevent the other from being reported
7. **`test_governor_fetches_tags_privileges_and_principals_in_parallel`** — the three initial fetch operations (tags, privileges, principals) run concurrently; verified by asserting that total elapsed time is closer to the slowest single fetch than the sum of all three (using mock delays)

---

## Phase 3: CLI entry point

### Step: `__main__.py`

Minimal `argparse` CLI:
- `--config-dir` — path to YAML config directory (required)
- `--warehouse-id` — SQL warehouse ID (required)
- `--dry-run` — print planned changes without executing

Auth handled by the Databricks SDK's default credential chain.

---

## Governor orchestration flow

```python
def run(config_dir, workspace_client, account_client, warehouse_id, dry_run=False):
    # 1. Discover + load + resolve YAML (shared)
    paths = discover_yaml_files(config_dir)
    raw_defs, raw_resources = load_raw_configs(paths)
    resolved = resolve_refs(raw_defs, raw_resources)
    config = ConfigFile.model_validate(resolved)  # resolved dict is already flat: {"catalogs": {...}}
    catalog_names = list(config.catalogs.keys())

    # 2. Parallel initial fetch (shared helpers)
    uc_helper = UnityCatalogHelper(workspace_client, warehouse_id)
    acct_helper = AccountHelper(account_client)
    with ThreadPoolExecutor() as pool:
        actual_tags_f = pool.submit(uc_helper.fetch_actual_tags, catalog_names)
        actual_privs_f = pool.submit(uc_helper.fetch_actual_privileges, catalog_names)
        principals_f = pool.submit(acct_helper.fetch_principals)
        actual_tags = actual_tags_f.result()
        actual_privileges = actual_privs_f.result()
        principals_f.result()

    # 3. Tags workflow (independent)
    desired_tags = compile_desired_tags(config)
    tag_diff = compute_tag_diff(desired_tags, actual_tags)
    if not dry_run:
        execute_tag_diff(uc_helper, tag_diff)

    # 4. Privileges workflow (independent, receives desired_tags as input)
    desired_privileges = compile_desired_privileges(config, desired_tags)
    acct_helper.validate_principals(extract_principals(desired_privileges))
    privilege_diff = compute_privilege_diff(desired_privileges, actual_privileges)
    if not dry_run:
        execute_privilege_diff(uc_helper, acct_helper, privilege_diff)

    return tag_diff, privilege_diff
```

---

## Error Handling

All custom exceptions inherit from `GovernorError` (defined in `types.py`), allowing callers to catch any governor error generically or handle specific cases.

**Error collection strategy:** Errors that can be detected statically (missing `$ref` keys, duplicate definition keys, unknown principals) are collected and reported together rather than failing on the first occurrence. This gives the user a complete picture of what needs fixing. The governor raises a single `GovernorError` with all collected issues listed in the message.

**Runtime errors** (SQL execution failures, API timeouts) fail immediately since they indicate an infrastructure problem that won't resolve by continuing.

---

## Logging

Use Python's `logging` module throughout. The governor configures a logger at the package level (`uc_abac_governor`).

| Level | Usage |
|-------|-------|
| `INFO` | Summary of each workflow: "Tags: 3 to add, 1 to update, 2 to remove" |
| `INFO` | Each applied change: `[ADD] catalog.schema.table env=prod`, `[GRANT] SELECT on catalog.schema.table to data_engineers` |
| `DEBUG` | SQL statements being executed, raw query results, detailed diff contents |
| `WARNING` | Non-fatal issues: e.g., a policy that matches zero objects |
| `ERROR` | Validation failures, SQL execution errors |

Dry-run mode logs planned changes at `INFO` level with a `[DRY RUN]` prefix.

---

## Open Design Decisions

1. **Tag value matching in policies:** The plan assumes exact matching (including `None` for valueless). So a policy with `tags: {sales: ~}` matches objects with a valueless `sales` tag only. If `~` should mean "any value", the compiler logic changes slightly. Defaulting to exact match for now.

2. **System table names:** The exact column names and table paths for tags and grants in `system.information_schema` will be verified against Databricks documentation during implementation. The queries in the stubs are representative but may need adjustment.

---

## Verification

1. **Unit tests:** `pytest tests/` after each red-green cycle
2. **Dry-run mode:** `python -m uc_abac_governor --config-dir ./configs --warehouse-id <id> --dry-run`
3. **Integration test (manual):** Run against a Databricks workspace with a test catalog, verify tags and grants are applied correctly, run again to verify idempotency
