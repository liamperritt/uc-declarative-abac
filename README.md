# UC Declarative ABAC

The UC Declarative ABAC framework lets Databricks customers define their Attribute-Based Access Control (ABAC) governance model via **declarative YAML files**. Define once, version in Git, and deploy to Unity Catalog—including as a **GitHub Action** from a repo containing your YAML configs.

## Overview

Instead of managing grants, tags, and policies manually in the Databricks workspace, you describe your ABAC governance model in YAML. The engine reads your configs, queries the UC system tables to determine the current state of deployed resources, computes a diff between the desired and actual state, and then applies only the changes required to bring UC in line with your configs.

Configs are split into two namespaces:

- **`definitions:`** — environment-agnostic, reusable templates (catalogs, schemas, tables, volumes, functions, ABAC policies).
- **`resources:`** — concrete, deployable instances (e.g., governed tags, catalogs and their contents) that can compose definitions into real UC objects.

Definitions define *what* exists; resources define *where* it gets deployed.

> **Note:** Definitions are not mandatory. You can define all of your governance directly under `resources:` without using `definitions:` at all. Definitions exist to reduce config duplication when the same logical objects appear in multiple places — for example, an ABAC policy that is applied across many catalogs, schemas that are replicated across environment catalogs (dev, test, prod), or bronze tables that exist across multiple locale-based schemas.

## Quick Start

Env-based auth (CI, GitHub Actions, Databricks Apps):

```bash
export DATABRICKS_HOST=https://<workspace>.cloud.databricks.com
export DATABRICKS_TOKEN=<personal-access-token>
python -m uc_declarative_abac --config-dir tests/e2e/configs --warehouse-id <warehouse-id> --enable-tag-management --enable-privilege-management --dry-run
```

Local development via `~/.databrickscfg` profile:

```bash
python -m uc_declarative_abac --config-dir tests/e2e/configs --warehouse-id <warehouse-id> --profile <profile-name> --enable-tag-management --enable-privilege-management --dry-run
```

### Authentication

The engine delegates authentication to the Databricks SDK's [unified authentication](https://docs.databricks.com/aws/en/dev-tools/auth/unified-auth) layer, so any mechanism the SDK supports will work. Common options:

| Mechanism | Required inputs | Typical use |
|---|---|---|
| Personal Access Token (PAT) | `DATABRICKS_HOST`, `DATABRICKS_TOKEN` | CI, scripted runs, GitHub Actions |
| OAuth M2M client credentials | `DATABRICKS_HOST`, `DATABRICKS_CLIENT_ID`, `DATABRICKS_CLIENT_SECRET` | Service-principal automation |
| Azure service principal | `DATABRICKS_HOST`, `ARM_CLIENT_ID`, `ARM_CLIENT_SECRET`, `ARM_TENANT_ID` | Azure Databricks workspaces |
| CLI profile | `--profile <name>` + matching entry in `~/.databrickscfg` | Local development |
| Default profile | `[DEFAULT]` section in `~/.databrickscfg` (no `--profile` flag needed) | Local development |
| Metadata service / managed identity | Runtime-supplied credentials | Databricks Apps, cluster-bound runs |

Resolution precedence matches the SDK's unified-auth chain: explicit `--profile` takes precedence, followed by env vars, `~/.databrickscfg`, and finally the metadata service. Omit `--profile` entirely to let the SDK pick whichever source is configured in the current environment.

> **Required permissions.** Whichever identity the engine authenticates as (typically a service principal for automation) must hold:
> - **Workspace admin** on the target workspace — needed to execute SQL on the configured warehouse and manage UC object owners.
> - **Metastore admin** on the target metastore — needed to create/alter catalogs, schemas, tables, volumes, functions, tags, grants, masks, and filters.
> - **Governed tag creator/manager** on the account — needed to create and update account-level governed tags (tag policies) under `resources.governed_tags`.

### GitHub Action

The repo ships a composite GitHub Action at `deploy/action.yml` so any other repo that stores its governance YAML in Git can reconcile Unity Catalog on every push / PR / schedule without installing the package or scripting a Python run. Reference it as `liamperritt/uc-declarative-abac/deploy@<ref>` (where `<ref>` is a tag, branch, or commit SHA).

**Inputs:**

| Input | Required | Default | Description |
|---|---|---|---|
| `config-dir` | yes | — | Path to the YAML config directory, relative to the caller's repo root |
| `warehouse-id` | yes | — | SQL warehouse ID used to execute UC queries |
| `profile` | no | `''` | Databricks CLI profile name from `~/.databrickscfg`; omit to use env-based auth (see the [Authentication](#authentication) table) |
| `dry-run` | no | `'false'` | Print planned changes without executing when `'true'` |
| `use-workspace-scim` | no | `'false'` | Fetch principals from the workspace SCIM API instead of the account SCIM proxy when `'true'`. The account-level system groups `account users` and `account admins` are automatically included, since the workspace SCIM API does not surface them |
| `enable-tag-management` | no | `'false'` | Permit the engine to create/update/remove tag assignments on securables |
| `enable-privilege-management` | no | `'false'` | Permit the engine to `GRANT`/`REVOKE` privileges |
| `enable-taggable-management` | no | `'false'` | Permit the engine to update attributes (owner, etc.) on existing catalogs/schemas/tables/volumes |
| `enable-taggable-creation` | no | `'false'` | Permit the engine to create catalogs/schemas/tables/volumes declared in config but absent from UC |
| `manage-tags-for-catalogs` | no | `'*'` | Comma-separated catalog names to scope tag management to (default `'*'` = all configured catalogs). No effect unless `enable-tag-management` is set |
| `manage-privileges-for-catalogs` | no | `'*'` | Comma-separated catalog names to scope privilege management to (default `'*'` = all configured catalogs). No effect unless `enable-privilege-management` is set |
| `manage-taggables-for-catalogs` | no | `'*'` | Comma-separated catalog names to scope taggable attribute updates (e.g. owner) to (default `'*'` = all configured catalogs). Function attributes always flow through. No effect unless `enable-taggable-management` is set |
| `create-taggables-for-catalogs` | no | `'*'` | Comma-separated catalog names to scope creation of missing catalogs/schemas/tables/volumes to (default `'*'` = all configured catalogs). Function creation always flows through. No effect unless `enable-taggable-creation` is set |
| `retain-tag-prefixes` | no | `'class.'` | Comma-separated tag-key prefixes the engine must never remove from securables, even when absent from config (it may still add/update them). Defaults to `'class.'` to protect UC auto data classification tags. Set to an empty string to allow removing any unconfigured tag |
| `enable-governed-tag-deletion` | no | `'false'` | Permit the engine to delete governed tags present in the account but absent from config. Requires interactive confirmation unless `force: 'true'` — in CI you must set `force` or the run errors out |
| `force` | no | `'false'` | Skip every interactive confirmation prompt and auto-confirm destructive actions. Required in CI when any destructive gate is set |
| `max-parallel-changes` | no | `'8'` | Max worker threads used per (securable_type, change_type) execution batch. Set to `'1'` to disable parallelism and force sequential execution |

**Example workflow in a caller repo** (`.github/workflows/deploy-uc-abac-governance.yml`):

```yaml
name: Deploy UC ABAC governance
on:
  pull_request:
    paths: ['configs/**']
  push:
    branches: [main]
    paths: ['configs/**']
  schedule:
    # It is recommended to schedule daily, preferrably once in the morning and once in the evening
    - cron: '0 22 * * *'  # ~8–9am Sydney time — revoke any privileges whose expiry_date has just passed
    - cron: '0 7 * * *'   # ~5–6pm Sydney time — re-sync to catch any drift introduced during the day

jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: liamperritt/uc-declarative-abac/deploy@v0.3.0
        with:
          config-dir: configs/
          warehouse-id: ${{ vars.DATABRICKS_WAREHOUSE_ID }}
          enable-tag-management: 'true'
          enable-privilege-management: 'true'
          dry-run: ${{ github.event_name == 'pull_request' }}
          force: 'true'
        env:
          DATABRICKS_HOST: ${{ secrets.DATABRICKS_HOST }}
          DATABRICKS_TOKEN: ${{ secrets.DATABRICKS_TOKEN }}
```

Swap `DATABRICKS_TOKEN` for `DATABRICKS_CLIENT_ID` + `DATABRICKS_CLIENT_SECRET` for OAuth M2M, or the Azure SP variables for Azure Databricks. Pinning to an immutable ref (e.g. a commit SHA or a signed tag) is recommended over `@main`.

## What You Can Define in YAML

### Definitions (reusable templates)

- **Catalog definitions** — top-level templates that list the schemas and policies a catalog should contain. You can define the canonical shape of a catalog once, then have a catalog **resource** `$ref` the definition and override only what differs between environments.
- **Schema definitions** — schema templates listing their child tables, volumes, and functions.
- **Table definitions** — table definitions tied to a schema definition.
- **Volume definitions** — volume definitions tied to a schema definition.
- **Function definitions** — UDF definitions with parameters and return expressions.
- **Policy definitions** — ABAC policies for column masking, row filtering, and grants.

### Resources (deployed UC objects)

- **Governed tags** — enforced usage rules for UC governed tags with allowed values, allowed principals, and comments.
- **Catalogs** — usually a thin `$ref` to a catalog definition with optional overrides (e.g. a different `name` or `tags` for a test vs prod environment). Can also be written fully inline when no reuse is needed.
- **Schemas, tables, volumes, functions, mask/filter ABAC policies** — concrete instances that can reference relevant definitions. Generally you shouldn't need to declare these at the resource level because they're pulled in transitively via the catalog definition. BUt both options are supported.

### Metadata on all objects

- **Owners** — set or update owners on catalogs, schemas, tables, volumes, and functions.
- **Comments** — manage descriptions on UC objects (except for tables and columns due to UC view limitations).
- **Tags** — key-value or valueless tags (using `~`) applied to any object.
- **RFA destinations** — configure where access requests are sent for governed objects.

### Principal naming conventions

When specifying principals for `owner`, `to`, `except`, or grant targets, use the appropriate identifier for the type of principal:

| Principal type | Identifier to use | Example |
|----------------|-------------------|---------|
| **User** | Email / username | `jane.doe@company.com` |
| **Group** | Display name | `data_engineers` |
| **Service principal** | Display name | `sp_data_governor` |

> **Note:** Service principal display names must be unique within the account. If two service principals share the same display name, the engine cannot resolve the intended principal and the deployment will fail.

## How It Works

| Use case | Flow |
|----------|------|
| **Column masking** | Policy definitions with `type: mask` → engine creates Unity Catalog ABAC masking policies that apply a function to tagged columns. |
| **Row filtering** | Policy definitions with `type: filter` → engine creates Unity Catalog ABAC row-filter policies using the referenced function. |
| **GRANTs** | Policy definitions with `type: grant` → engine computes grants from tag mappings and executes the corresponding `GRANT` statements. |
| **UC objects & tags** | Catalog resources compose schema, table, volume, and function definitions → engine creates/updates/tags them in each target catalog. |

You maintain YAML as the source of truth; the engine turns it into UC objects and permissions.

## YAML Config Structures

Configs use **dictionaries keyed by definition IDs**. The recommended convention is to use `|`-delimited keys that mirror the Unity Catalog path of the object — e.g. `my_catalog` for a catalog, `my_catalog|sales` for a schema, `my_catalog|sales|orders` for a table. This matches the Databricks Terraform provider's composite resource IDs (e.g. `<metastore_id>|<name>` for UC connections). For reusable, catalog-agnostic definitions (typically policies and shared functions), a `<tag_key/domain>|<name>` style works well — e.g. `pii|mask_pii`. The `|` delimiter is a convention only and is not enforced by the engine — keys can be any valid YAML string.

Key conventions by type:

| Type | Convention | Example |
|------|-----------|---------|
| catalogs | `<catalog_name>` | `operations` |
| schemas | `<catalog_name>\|<schema_name>` | `operations\|sales` |
| tables | `<catalog_name>\|<schema_name>\|<table_name>` | `operations\|sales\|orders` |
| volumes | `<catalog_name>\|<schema_name>\|<volume_name>` | `operations\|landing\|raw_events` |
| functions (catalog-specific) | `<catalog_name>\|<schema_name>\|<function_name>` | `operations\|shared\|mask_pii_email` |
| functions (cross-catalog, reusable) | `<tag_key/domain>\|<function_name>` | `pii\|mask_pii` |
| policies (cross-catalog, reusable) | `<tag_key/domain>>\|<policy_name>` | `pii\|mask_pii_email` |

These keys are the stable identity for each entity and let you reference entities across files via `$defs/<type>/<key>` or `$ref: $defs/<type>/<key>` syntax (inspired by JSON Schema's `$defs` and `$ref` keywords) which also supports selective config overrides (see the **Overrides** section below).

Any definition type (catalogs, schemas, tables, volumes, functions, mask/filter policy) can be promoted to a concrete resource by placing it under `resources:` with a `$ref`/`$defs` reference to the definition. For catalogs this is the usual pattern — the catalog definition captures the shape, and a resource catalog references it. For leaf types (table, volume, function) you can also promote them directly when you need a single deployed instance outside of a catalog composition; these require `catalog_name`/`schema_name` to be set.

### Definitions

Definition configs are reusable templates for every UC object type — catalogs, schemas, tables, volumes, functions, and policies. The recommended pattern is to structure your definitions like the UC catalog itself: one top-level `catalog` definition that composes the schemas, policies, tags, and other catalog-level metadata, and then nested schema / table / volume / function definitions organised by catalog and schema. This keeps definitions close to the UC object they describe and makes the resource side of the config trivial — usually just a `$ref` to the catalog definition with a few overrides (e.g. a name change between prod and test environments).

Cross-catalog reusable definitions (typically ABAC policies and shared functions) can live outside the catalog tree under `definitions/policies/` or `definitions/functions/` and be `$ref`'d from multiple catalogs.

#### Catalog definitions

Catalog definitions capture the canonical shape of a catalog — its tags, owner, RFA destinations, catalog-level policies, and the list of schemas it contains. Key convention: `<catalog_name>`. A catalog definition composes schemas and policies via `$ref`/`$defs` entries; a resource catalog then references the whole definition and overrides only what differs between environments (commonly just `name` and a few tags).

```yaml
# definitions/catalogs/operations/operations.yaml
definitions:
  catalogs:
    operations:
      name: operations
      comment: Operations catalog
      owner: data_platform_team
      location: s3://operations-managed/operations  # optional managed location, set at CREATE only
      rfa_destinations:
        - data-governance@company.com
      policies:
        - $defs/policies/domain|grant_finance_read
        - $defs/policies/pii|mask_pii_email
      schemas:
        - $defs/schemas/operations|sales
        - $defs/schemas/operations|landing

# resources/catalogs/operations_prod.yaml
resources:
  catalogs:
    operations_prod:
      $ref: $defs/catalogs/operations
      name: operations_prod
      tags:
        env: prod
```

#### Schema definitions

Schema definitions capture the shape of a schema: name, comment, owner, tags, policies, and RFA (Request For Access) destinations. Key convention: `<catalog_name>|<schema_name>` (e.g. `operations|sales`, `operations|landing`). Each schema definition lists the **tables**, **volumes**, **functions**, and/or **policies** it contains as `$ref`/`$defs` entries. A catalog definition references which schemas to include; the engine creates each schema and its listed children inside the owning catalog.

```yaml
# definitions/operations/schemas/sales/sales.yaml
definitions:
  schemas:
    operations|sales:
      name: sales
      comment: Sales and revenue datasets
      owner: sales_engineering
      tags:
        operations: ~
      policies:
        - $defs/policies/domain|grant_read_on_sales
      tables:
        - $defs/tables/operations|sales|orders

# definitions/people/schemas/hr/hr.yaml
definitions:
  schemas:
    people|hr:
      name: hr
      comment: HR data (restricted)
      owner: hr_analytics
      rfa_destinations:
        - hr-access@company.com
      tags:
        people: ~

# definitions/platform/schemas/landing/landing.yaml
definitions:
  schemas:
    platform|landing:
      name: landing
      comment: Landing zone for raw data
      owner: data_platform_team
      tags:
        platform: ~
        zone: landing
      volumes:
        - $ref: $defs/volumes/platform|landing|files
          owner: hr_analysts

# definitions/platform/schemas/shared/shared.yaml
definitions:
  schemas:
    platform|shared:
      name: shared
      comment: Shared functions and utilities
      owner: data_platform_team
      tags:
        shared: ~
      functions:
        - $defs/functions/platform|shared|mask_pii_email


# resources/catalogs/platform_prod/schemas/shared/shared.yaml
resources:
  schemas:
    platform|shared_prod:
      $ref: $defs/schemas/platform|shared
      catalog_name: platform_prod

# resources/catalogs/platform_test/schemas/shared/shared.yaml
resources:
  schemas:
    platform|shared_test:
      $ref: $defs/schemas/platform|shared
      catalog_name: platform_test
```

#### Table definitions

Tables are defined in a flat dictionary under `definitions: tables:`. Key convention: `<logical_catalog>|<schema_name>|<table_name>` (e.g. `operations|sales|orders`).

```yaml
# definitions/operations/schemas/sales/tables/orders.yaml
definitions:
  tables:
    operations|sales|orders:
      name: orders
      owner: sales_engineering
      comment: Orders fact table
      location: s3://operations-external/sales/orders  # optional external location (immutable; CREATE-only)
      rfa_destinations:
        - sales-data@company.com
      tags:
        classification: internal
        sales: ~
      policies:
        - $ref: $defs/policies/pii|mask_pii_email

# definitions/people/schemas/hr/tables/employees.yaml
definitions:
  tables:
    people|hr|employees:
      name: employees
      owner: hr_analytics_team
      tags:
        people: ~
      columns:
        - name: employee_id
        - name: full_name
          tags:
            pii: name
        - name: email
          tags:
            pii: email
        - name: salary
          tags:
            classification: confidential
```

Row-level and column-level security are applied via **tag-based ABAC policies**: tag columns and tables, and let policy definitions match against those tags to apply masking, filtering, and grants across all matching objects (see [policy definitions](#policy-definitions)).

Column-level fields:
- **`name`** — the column name (required).
- **`type`** — the column data type (optional). If provided and the table does not yet exist, the framework will attempt to create it with the specified column types.
- **`tags`** — key-value or valueless tags applied to the column. These can be matched by ABAC policy definitions.

Table-level fields (in addition to the common fields `name`, `comment`, `owner`, `tags`, `rfa_destinations`):
- **`columns`** — list of column-level configurations (see above).
- **`policies`** — list of policy `$ref`/`$defs` entries or inline policies scoped to this table.
- **`location`** — external storage location (URI). Setting `location` on a new table makes it an external table; the LOCATION clause is included in `CREATE TABLE`. External location is **immutable after creation**.

Comments are supported on managed and external tables, but **not on views**. If a table's actual `table_type` is `VIEW`, a comment change is refused with a logged error (set the comment in the view definition instead). Column-level comments are not currently supported.

#### Volume definitions

Volumes are defined under `definitions: volumes:`. Key convention: `<logical_catalog>|<schema_name>|<volume_name>` (e.g. `platform|landing|raw_events`).

```yaml
# definitions/platform/schemas/landing/volumes/raw_events.yaml
definitions:
  volumes:
    platform|landing|raw_events:
      name: raw_events
      comment: Landing volume for raw event files
      owner: data_platform_team
      tags:
        landing: ~

# resources/catalogs/platform_prod/schemas/landing/volumes/raw_events.yaml
resources:
  volumes:
    platform_prod|landing|raw_events:
      $ref: $defs/volumes/platform|landing|raw_events
      catalog_name: platform_prod
      schema_name: landing
```

#### function definitions

Functions are defined under `definitions: functions:`. Key convention: `<logical_catalog>|<schema_name>|<function_name>` (e.g. `platform|shared|mask_pii_email`). ABAC policies can leverage these functions by referencing the function definition inline, or via the fully qualified UC function resource name.

```yaml
# definitions/platform/schemas/shared/functions/mask_pii_email.yaml
definitions:
  functions:
    platform|shared|mask_pii_email:
      name: mask_email
      comment: Masks email for PII policy
      owner: data_platform_team
      parameters:
        - name: address
          type: string
      return: "CONCAT('***', SUBSTRING(address, -4))"

# definitions/platform/schemas/shared/functions/filter_by_region.yaml
definitions:
  functions:
    platform|shared|fn_filter_by_region:
      name: fn_filter_by_region
      comment: Users can only see records from their region
      parameters:
        - name: region
          type: string
      return: |-
        (region = 'AFRICA' AND is_account_group_member('africa_users'))
        OR (region = 'AMERICA' AND is_account_group_member('america_users'))
        OR (region = 'EUROPE' AND is_account_group_member('europe_users'))
        OR (region = 'ASIA' AND is_account_group_member('asia_users'))
        OR (region = 'MIDDLE EAST' AND is_account_group_member('middle_east_users'))
```

#### Policy definitions

ABAC policies are defined under `definitions: policies:`. Key convention: `<tag_key/domain>|<policy_name>` (e.g. `pii|mask_pii_email`). Three types:

- **`mask`** — applies a function to columns matching a tag; uses `to` / `except` to control who sees masked vs. unmasked data.
- **`filter`** — applies a row-filter function to tables matching a tag; uses `to` / `except` to control who is filtered.
- **`grant`** — assigns privileges on objects matching a tag to listed principals; supports `expiry_date`.

Policy fields:
- **`to`** — the principals the policy is applied to (e.g. who sees the masked value, who gets the row filter applied, or who receives the grant). For **`mask`** and **`filter`** policies this is optional and defaults to `account users` (the all-users system group) when omitted; for **`grant`** policies it is required.
- **`except`** — (`mask` and `filter` types only) principals exempted from the policy. Exempted principals see the original unmasked data or unfiltered rows.
- **`has_tags`** — a tag-match block that scopes the policy to tagged objects (grants scope to securables within the attached level; masks/filters scope to tagged tables). AND semantics across multiple entries. Supports `'*'` wildcard tag values for matching only against the tag key. See the paragraphs below the examples for the full per-type behaviour.
- **`has_any_of_tags`** — the same as `has_tags`, but with **OR** semantics: an object matches if it carries **any one** of the listed tags. Supports the same `'*'` wildcard values. May be specified on its own or alongside `has_tags`; when both are present they combine as **AND-of-groups** — an object must match **all** `has_tags` **and** at least one `has_any_of_tags`. Available on all three policy types.
- **`column`/`columns`** — (`mask` and `filter` types only) a single column, or an ordered list of column slots. Every slot is passed as an argument to the `function` in declaration order, so the list must match the function's parameter signature. A slot is one of two kinds:
  - **alias column** — has an `alias` (a local name used to reference the column within this policy) and a `has_tags` and/or `has_any_of_tags` block that selects the actual table column by tag (at least one of the two is required). For **mask** policies, the **first** column in the list must be an alias column — it is the one the mask function is applied to (i.e. it becomes `ON COLUMN <alias>` in the generated SQL) and is also passed as the first argument to the function.
  - **constant column** — has a single `constant: <value>` and no tags. It is passed to the function as a constant rather than a table column, which is useful for parameterising a shared masking/filtering function per policy (e.g. a per-policy replacement value).
- **`privileges`** — (`grant` type only) the UC privileges to assign. Supported values include the concrete UC privileges (`select`, `modify`, `create_table`, `create_schema`, `create_function`, `create_volume`, `use_catalog`, `use_schema`, `read_volume`, `write_volume`, `execute`, `refresh`, `create_materialized_view`, `create_model`, `create_model_version`, `browse`, `all_privileges`, `external_use_schema`, `manage`) and four shorthand **abstractions** that each expand to a fixed set of UC privileges:

  | Abstraction | Expands to |
  |---|---|
  | `read` | `select`, `read_volume`, `execute` |
  | `edit` | `modify`, `write_volume`, `refresh` |
  | `use` | `use_catalog`, `use_schema` |
  | `create` | `create_table`, `create_schema`, `create_function`, `create_volume`, `create_materialized_view`, `create_model`, `create_model_version` |

  Expansion is flat (not securable-type-aware); each expanded privilege then flows through the same compatibility filter and `use_catalog`/`use_schema` cascade as a concrete privilege would. So `read` on a table-matched policy emits `SELECT` (the volume/function-specific entries drop), and `use` on a catalog-attached policy matching a deep child cascades `USE_CATALOG` to the catalog and `USE_SCHEMA` to the containing schema. Abstractions and concrete privileges can be mixed freely in the same list.
- **`expiry_date`** — (`grant` type only) ISO 8601 date (`YYYY-MM-DD`) after which the grant is automatically revoked.

```yaml
# definitions/sred/policies/pii/mask_email_pii.yaml
definitions:
  policies:
    pii|mask_email_pii:
      name: mask_email_pii
      comment: Mask email PII from all users except account admins
      type: mask
      column:
        alias: email
        has_tags:
          pii: email
      function: platform.abac.mask_email_pii
      to:
        - account users
      except:
        - pii_viewers

# definitions/policies/pii/mask_customer_name_pii.yaml
definitions:
  policies:
    pii|mask_retail_segment_customer_names_pii:
      name: mask_retail_segment_customer_names_pii
      comment: Mask retail-segment customer names (not commercial-segment customer names) from all users except account admins
      type: mask
      has_tags:
        domain: customer
      columns:
        - alias: name
          has_tags:
            pii: '*'
            class.name: '*'
        - alias: segment
          has_tags:
            segment: '*'
      function: platform.abac.mask_retail_segment_customer_names_pii
      to:
        - account users
      except:
        - customer_pii_viewers

# definitions/policies/pii/mask_with_fixed_value.yaml
# A shared mask function reused across policies, parameterised by a constant
# replacement value. The first column (alias) is the masked column; the constant
# is passed as the second function argument and rendered as 'REDACTED' in SQL.
definitions:
  policies:
    pii|mask_email_redacted:
      name: mask_email_redacted
      type: mask
      columns:
        - alias: email
          has_tags:
            pii: email
        - constant: REDACTED
      function: platform.abac.mask_with_value
      to:
        - account users

# definitions/policies/region/filter_trips_by_region.yaml
definitions:
  policies:
    region|filter_trips_by_region:
      name: filter_trips_by_region
      comment: Users can only see high sensitivity trips to or from their region
      type: filter
      has_tags:
        trips: '*'
        sensitivity: high
      columns:
        - alias: from_region
          has_tags:
            from_region: '*'
        - alias: to_region
          has_tags:
            to_region: '*'
      function:
        name: to_or_from_region_filter
        parameters:
          - name: from_region
            type: string
          - name: to_region
            type: string
        return: |-
          (
            (from_region = 'AFRICA' AND is_account_group_member('africa_users'))
            OR (from_region = 'AMERICA' AND is_account_group_member('america_users'))
            OR (from_region = 'EUROPE' AND is_account_group_member('europe_users'))
            OR (from_region = 'ASIA' AND is_account_group_member('asia_users'))
            OR (from_region = 'MIDDLE EAST' AND is_account_group_member('middle_east_users')
          ) OR (
            (to_region = 'AFRICA' AND is_account_group_member('africa_users'))
            OR (to_region = 'AMERICA' AND is_account_group_member('america_users'))
            OR (to_region = 'EUROPE' AND is_account_group_member('europe_users'))
            OR (to_region = 'ASIA' AND is_account_group_member('asia_users'))
            OR (to_region = 'MIDDLE EAST' AND is_account_group_member('middle_east_users')
          )
      to:
        - account users
      except:
        - account admins

# definitions/policies/business_area/grant_read_on_sales.yaml
definitions:
  policies:
    business_area|grant_read_on_sales:
      name: grant_read_on_sales
      comment: Grant sales team access to sales data (until May 2026)
      type: grant
      has_tags:
        business_area: sales
      privileges:
        - select
      to:
        - data_engineers
        - sales_team
        - sp_sales_job_runner
      expiry_date: 2026-05-01
```

For **grant** policies attached at a given level, the optional `has_tags` property is scoped to match only the tagged objects within that level — a policy on a schema only matches the schema and the tables and volumes within that schema; a policy on a table only matches that table. If multiple tags are specified, the policy is only applied to objects that match **all** of the listed tags (AND semantics). Use `has_any_of_tags` instead to match objects that carry **any one** of the listed tags (OR semantics); specifying both restricts to objects matching all `has_tags` **and** at least one `has_any_of_tags`. Omitting both tag-match properties for a **grant** policy applies the privileges directly on the object to which the policy is attached.

For **grant** policies that list `use_catalog` or `use_schema`, the privilege is emitted against the correct parent securable rather than the tag-matched child — a `use_catalog` privilege on a policy matching a schema, table, or volume is emitted on the containing catalog, and a `use_schema` privilege on a policy matching a table or volume is emitted on the containing schema. This cascade is bounded by the policy's attachment level: a policy attached at a schema cannot hand out `use_catalog` on its parent catalog, and a policy attached at a table cannot hand out `use_catalog` or `use_schema` on its ancestors — those targets are outside the policy's scope and are dropped. To grant traverse privileges above the attachment level, attach a separate grant policy at that higher level (or use a tagless catalog-level policy).

If a **mask** or **filter** policy specifies the optional `has_tags` property, this matches against tagged **tables** only. Use the mandatory `columns.[*]` tag-match (`has_tags` and/or `has_any_of_tags`) to match against tagged columns that you want to use for row filtering logic, or that you want to apply column masking to. As above, multiple `has_tags` entries require **all** tags to be present (AND semantics), while `has_any_of_tags` matches tables/columns carrying **any one** of the listed tags (OR semantics); the two combine as AND-of-groups when both are given. The values of the tagged column are passed as a single parameter to the specified function.

For mask and filter policies, the `function` property can either be the name of an existing UC function (string), or an inline function definition. A string function name may be **partially qualified** and is auto-completed from the policy's own catalog/schema: a bare `mask_email` becomes `<catalog>.<schema>.mask_email` and a `shared.mask_email` becomes `<catalog>.shared.mask_email`, while an already fully-qualified `catalog.schema.fn` is left unchanged. (A bare name on a catalog-level policy has no schema to prepend, so it falls back to the catalog's `default` schema — the same place inline catalog-level functions are deployed.) When defining an inline function, the function resource will be deployed into the same catalog and schema as the policy. If the policy is attached at the catalog level, then the inline function will be deployed to the `default` schema of that catalog. If this results in duplicate functions with identical names, the framework will raise an error. If several policies reference a single reusable function definition as an inline function via `$defs/functions/<fn_name>`, then make sure to override the function `name` field as necessary to avoid a "Duplicate functions" error.

### Resources

Resource configs are concrete, deployable instances (e.g., catalogs and their contents) that can compose definitions into real UC objects.

#### Governed Tags

Governed tags specify a tag name with a enforced set of allowed values. They are defined under `resources: governed_tags:` (not definitions) because they are account-level singletons—there is no catalog-scoped variant. The dictionary key is used as the tag name if `name` is not provided. All governed tags should exclusively be created through this framework.

- **`name`** — the governed tag key.
- **`description`** — a human-readable description of the governed tag's purpose. `comment` is still accepted as a backward-compatible alias on input.
- **`allowed_values`** — the fixed list of values that can be assigned to this tag. ABAC policies reference these tag key-value pairs to determine which columns to mask, which rows to filter, or which objects to grant access on.
- **`assigners`** — the list of principals (users, groups, or service principals by display name) who are permitted to `ASSIGN` the tag to Unity Catalog objects. This is reconciled via the Account Access Control Proxy rule-set API: principals listed here receive the ASSIGN role on the tag policy, principals not listed have it revoked. Useful for letting users test tag assignments within `dev` catalogs that are not governed by this framework — manually assigning a governed tag to a UC object that *is* governed will be reverted on the next run. The framework only manages `assigners` on tags it knows about (declared in config); tags present on the account but absent from config retain their existing ACLs untouched.

```yaml
# resources/governed_tags/pii.yaml
resources:
  governed_tags:
    pii:
      name: pii
      description: Personally identifiable information tag
      allowed_values:
        - name
        - address
        - drivers_license
      assigners:
        - account users

# resources/governed_tags/classification.yaml
resources:
  governed_tags:
    classification:
      name: classification
      description: Data classification level
      allowed_values:
        - public
        - internal
        - confidential
        - restricted
      assigners:
        - data_governance_team
        - john.smith@company.com
        - sp_data_governor
```

Once a tag policy is created, you can apply it to tables, columns, schemas, and other UC objects via the `tags:` field on any definition or resource. ABAC policies then match against these tag key-value pairs (e.g. `pii: email`, `classification: confidential`) to enforce masking, filtering, or grants.

#### Catalogs

Catalogs are deployed by placing an entry under `resources: catalogs:`. The recommended form is a thin `$ref` to a matching catalog definition — this keeps all the interesting composition (schemas, policies, tags) in the definition, and leaves the resource side as a one-line pointer. Overrides can be applied on the `$ref` entry when a resource needs to differ from its definition (for example, a test catalog that reuses a prod definition but changes `name`, a couple of tags, or a function reference).

**Pattern 1 — thin `$ref` with optional overrides.** One catalog definition, multiple matching resource:

```yaml
# definitions/catalogs/operations/operations.yaml
definitions:
  catalogs:
    operations:
      name: operations
      comment: Operations catalog
      owner: data_platform_team
      policies:
        - $defs/policies/pii|mask_pii_email
      schemas:
        - $defs/schemas/operations_prod|sales
        - $defs/schemas/operations_prod|landing

# resources/catalogs/operations_prod.yaml
resources:
  catalogs:
    operations_prod:
      $ref: $defs/catalogs/operations
      name: operations_prod
      tags:
        env: prod

# resources/catalogs/operations_test.yaml
resources:
  catalogs:
    operations_test:
      $ref: $defs/catalogs/operations
      name: operations_test
      tags:
        env: test
```

**Pattern 2 — fully inline.** If you don't need reuse, skip the definition layer entirely and declare the catalog straight under `resources:`:

```yaml
# resources/catalogs/operations_prod.yaml
resources:
  catalogs:
    operations_prod:
      name: operations_prod
      owner: data_platform_team
      tags:
        env: prod
      policies:
        - $defs/policies/pii|mask_pii_email
      schemas:
        - $defs/schemas/operations|sales
```

### Overrides

Any `$ref` entry can include additional fields alongside the reference. These fields override the corresponding values from the definition, letting you customise a single instance without modifying the shared definition. For example, you can override `owner`, `rfa_destinations`, `comment`, `tags`, or `function` on a per-catalog or per-resource basis. Unspecified fields fall back to the definition.

Overrides also support nested references — you can nest `$ref` entries within an override to further customise child objects. For example, overriding a schema's `tables` list with specific table references that themselves carry overrides:

```yaml
resources:
  catalogs:
    operations_test:
      name: operations_test
      comment: TEST Operations catalog
      schemas:
        - $ref: $defs/schemas/operations|sales
          name: sales_staging
          tables:
            - $ref: $defs/tables/operations|sales|orders
            - $ref: $defs/tables/operations|sales|quotes
              comment: This table only exists in TEST
```

By default, overrides **recursively deep-merge** into the definition:

- **Maps merge key-wise.** Override keys take precedence; unspecified keys fall back to the definition. For example, you can override a single tag and the other tags from the definition are preserved.
- **Lists of identifier-bearing items merge by `name` (or `alias`).** Items in the override that match an item in the definition by identifier are recursively merged with it; unmatched override items are appended; unmatched definition items are preserved. This lets you add a new table to a schema definition's `tables` list, or tweak a single column, without re-listing every existing entry.
- **Lists of primitives are unioned with dedupe.** Useful for `privileges`, where you want to add `MODIFY` to a definition's `[SELECT]` without dropping `SELECT`.
- **Other shapes (mixed items, type mismatch, items without identifiers) fall back to replace.** The override wins entirely — there's no sensible way to align items.

If you need the legacy shallow-replacement behaviour (where any override of a list or map replaces it in its entirety), pass `--ref-override-strategy replace` on the CLI. The default is `merge`.

```yaml
# Definition
definitions:
  schemas:
    operations|sales:
      name: sales
      tags:
        domain: operations
        pii: "true"
      tables:
        - name: orders
          comment: Orders table
        - name: quotes
          comment: Quotes table

# Resource — override merges, doesn't replace
resources:
  catalogs:
    operations_test:
      schemas:
        - $ref: $defs/schemas/operations|sales
          tags:
            pii: "false"
            env: test                     # 'domain' preserved; 'pii' updated; 'env' added
          tables:
            - name: quotes
              comment: TEST quotes table  # merges with definition's 'quotes'
            - name: leads
            `comment: Leads table         # appended; 'orders' from def is preserved
```

---

## File Organization

The recommended convention is to **mirror the Unity Catalog directory structure** under `definitions/catalogs/`, so each catalog, schema, table, volume and function config file sits where you'd expect to find it in UC. Cross-catalog reusable content (policies, shared functions) lives outside the catalog tree under `definitions/policies/` or `definitions/functions/`. The resource side stays thin — typically one file per catalog that `$ref`s the matching catalog definition.

Recommended layout:

```
definitions/
├── catalogs/
│   └── operations/
│       ├── operations.yaml              # catalog definition
│       └── schemas/
│           ├── sales/
│           │   ├── sales.yaml           # schema definition
│           │   ├── tables/
│           │   │   ├── orders.yaml      # table definition
│           │   │   └── quotes.yaml
│           │   ├── functions/
│           │   │   └── lookup_region.yaml
│           │   └── CODEOWNERS
│           └── landing/
│               ├── landing.yaml
│               ├── volumes/
│               │   └── raw_events.yaml
│               └── CODEOWNERS
├── policies/                            # cross-catalog reusable policies
│   ├── pii/
│   │   └── mask_pii.yaml
│   └── domain/
│       └── grant_sales_read.yaml
└── functions/                           # cross-catalog reusable functions (optional)
    └── pii/
        └── mask_pii_email.yaml
resources/
├── catalogs/
│   ├── operations_prod.yaml             # thin $ref to the catalog definition
│   └── operations_test.yaml
└── governed_tags/
    ├── pii.yaml
    └── domain.yaml
CODEOWNERS
```

This folder structure is a recommendation, not enforced by the engine — the engine discovers every `.yaml` / `.yml` file under the config root and resolves references by definition key, not by file path. But keeping files where you'd expect them in a UC browser makes configs easy to navigate, and pairing each catalog definition with a matching one-line resource file is a clean split: **definitions describe what exists; resources describe where it gets deployed.**

## Deployment

The engine is designed to run in CI/CD. You can use it as a **GitHub Action** on a repository that holds your YAML files: on push or on a schedule, the action runs the engine against your configs and **declaratively deploys ABAC governance** to your Databricks workspace and Unity Catalog.

It is recommended to run the deployment whenever a new version of your YAML files is released, as well as running a scheduled deployment at least once per day (to reduce drift and to ensure features like the grant policy `expiry_date` work as intended).

> **Note:** By default, the engine assumes that securables (catalogs, schemas, tables, volumes) already exist in Unity Catalog and will only manage tags, grants, and policies on them. If you want the engine to create securables that don't exist yet, pass the `--enable-taggable-creation` flag.

### Deployment semantics

Not all object types are managed the same way:

| Category | Behaviour | Examples |
|----------|-----------|----------|
| **Governed tags** | Additive + deletes | Unconfigured governed tags are deleted from the account only if the "--enable-governed-tag-deletion" flag is set. |
| **UC objects & attributes** | Additive only (create/update, never deletes) | Catalogs, schemas, tables, volumes, functions, comments |
| **Tags & grant policies** | Additive + removals/revokes | Tag assignments on objects, `GRANT` statements |
| **Mask & filter policies** | Additive only (create/update) | Column masking policies, row filter policies |

Mask and filter policies are currently additive-only because Unity Catalog does not yet expose a system table to track existing mask/filter policy assignments. Once UC adds this capability, the engine will handle removals for these policy types as well, matching the behaviour of tags and grants.

> **Important — tag and grant drift:** For catalogs governed by this project, the engine treats the YAML configs as the sole source of truth for tags and privilege grants. If a tag or grant is manually added to an object in a governed catalog (e.g. via the Databricks UI or a direct SQL statement), the engine will remove it on the next run to re-sync with the declared config. All tag assignments and privilege grants for governed catalogs must be managed through these YAML files.

---

## Implementation Status

### Implemented

#### Core pipeline
- **YAML discovery** — recursively finds all `.yaml`/`.yml` files in a config directory
- **`$ref`/`$defs` resolution** — resolves `$defs/<type>/<key>` references with override support, circular reference detection, and unreferenced definition detection
- **Resource consolidation** — standalone `resources.schemas`, `resources.tables`, `resources.volumes` are restructured into the nested catalog hierarchy with parent auto-creation
- **Pydantic model validation** — full config validation with parent context injection (`catalog_name`, `schema_name`, `table_name`), `full_name` computed fields, null tag coercion, and duplicate resource detection

#### Governed tags domain
- **Governed tag compilation** — walks `resources.governed_tags`, emitting `GovernedTag` state with `description` and `allowed_values` per entry; dict key is used as the default tag name
- **Governed tag fetch** — account-level tag policies are retrieved via `WorkspaceClient.tag_policies.list_tag_policies` on `WorkspaceHelper`; runs in parallel with the other initial state fetches
- **Governed tag diffing** — computes creates and updates by comparing desired vs actual state; `allowed_values` is compared as a set so cosmetic YAML reordering does not trigger an update; tag policies present in the account but absent from YAML are left alone (no-delete invariant for this iteration)
- **Governed tag execution** — `create_tag_policy` for new entries; `update_tag_policy` with a precise `update_mask` (`description`, `values`, or both) per changed field on existing entries; allowed values are sorted before being sent to the SDK for deterministic output
- **Ordering** — governed tags are reconciled *before* catalog-scoped `SET TAGS` statements, so new tag keys exist in the account before assignments reference them
- **Assigner ACLs (`assigners`)** — for each governed tag declared in config, the engine reconciles the `ASSIGN` role on the tag policy via the Account Access Control Proxy rule-set API (`WorkspaceClient.account_access_control_proxy.{get_rule_set, update_rule_set}`). Rule-set fetches are scoped to the intersection of desired and actual tag names (1 + |intersection| API calls per run, dispatched concurrently). Tag policies present on the account but absent from config retain their existing assigner ACLs untouched — symmetric with the no-delete-by-default invariant for the rest of the resource. Read-modify-write with optimistic-concurrency etag preserves any non-ASSIGN grant rules across updates. Newly-created tags receive their `assigners` immediately after `create_tag_policy` returns the new tag id. Account ID is read from `WorkspaceClient.config.account_id`

#### Securables domain
- **Owner management** — detects owner drift between config and workspace; updates via WorkspaceClient API for all securable types (catalogs, schemas, tables, volumes, functions)
- **Function creation** — creates new functions via `CREATE FUNCTION` SQL with parameters and return expression (no `RETURNS` clause; UC infers the type)
- **Function replacement** — replaces existing functions whose parameters or definition have changed via `CREATE OR REPLACE FUNCTION` SQL
- **Single state query** — `fetch_actual_securables` combines attributes and function definitions in one UNION ALL query with `collect_list`/`sort_array`/`transform` aggregation for function parameters and table columns
- **RFA destinations** — per-securable Request-For-Access notification targets declared via the `rfa_destinations` field on any catalog/schema/table/volume/function. Each entry is classified at config-load via regex: email addresses, `http(s)://` URLs, or canonical Databricks notification-destination UUIDs; any other shape raises a config error listing every offender. Actual state is fetched per declared target via `WorkspaceClient.rfa.get_access_request_destinations` (parallel fanout, 404 treated as empty); diffs compare by destination id only (set-shaped, order-insensitive), and updates post via `update_access_request_destinations(..., update_mask="destinations")`. Gated by `--enable-taggable-management`. `rfa_destinations` is rejected on columns.

#### Tags domain
- **Tag compilation** — walks catalog → schema → table → column → volume hierarchy, emitting desired tags
- **Tag diffing** — computes adds, updates, and removes by comparing desired vs actual state from `information_schema.*_tags` system tables
- **Tag execution** — generates and executes `ALTER SET/UNSET TAGS` SQL, including `ALTER TABLE ... ALTER COLUMN ... SET/UNSET TAGS` for column-level tags
- **Tag types** — CATALOG, SCHEMA, TABLE, VOLUME, COLUMN

#### Policies domain (mask / filter ABAC)
- **Policy compilation** — walks catalog → schema → table hierarchy, emitting `MASK` and `FILTER` policy definitions; grant policies are filtered out and handled by the privileges domain
- **Tag-to-WHEN translation** — policy `has_tags` maps to a `WHEN` clause: `has_tag_value('k', 'v')` for concrete values, `has_tag('k')` for the `'*'` wildcard, AND-joined
- **Column-tag-to-MATCH-COLUMNS translation** — per-column `has_tags` maps to `MATCH COLUMNS <condition> AS <alias>` entries
- **MASK column split** — the first `columns[]` entry becomes `ON COLUMN <alias>`; remaining columns become `USING COLUMNS (...)` args
- **FILTER columns** — no `ON COLUMN`; all columns become `USING COLUMNS (...)` args
- **Parallel policy state fetch** — `WorkspaceClient.policies.list_policies` is invoked per configured catalog/schema/table concurrently via a `ThreadPoolExecutor(max_workers=32)` pool
- **Policy diffing** — computes creates and replaces keyed by `(securable_type, full_name, name)`; actual-only policies are silently skipped (UC policies are never deleted)
- **Policy execution** — generates and executes `CREATE POLICY` / `CREATE OR REPLACE POLICY` SQL with `ON`, `TO`, optional `EXCEPT`, `FOR TABLES`, optional `WHEN`, optional `MATCH COLUMNS`, `ON COLUMN` (MASK only), and `USING COLUMNS`
- **Policy model validation** — `MaskPolicyConfig` requires at least one column entry; `FilterPolicyConfig` allows an empty column list
- **Inline function definitions** — a mask or filter policy's `function` field can be either a fully qualified UC function name or an inline function definition (plain dict or `$ref` / `$defs/...` that resolves to a dict). The consolidator moves inline definitions into the policy's enclosing schema — or the catalog's `default` schema when the policy is attached at the catalog level — and rewrites the policy's `function` field to the synthesised full name. Duplicate-name collisions surface as `DuplicateResourceError` at model validation

#### Privileges domain
- **Privilege compilation** — matches grant policies against desired tags with AND semantics, scoped to the policy's attached securable and its children
- **Abstract privilege names** — `read`, `edit`, `use`, and `create` are accepted in a policy's `privileges:` list as shorthands that expand to a fixed set of concrete UC privileges; the existing compatibility filter and `USE_CATALOG`/`USE_SCHEMA` cascade then apply per emitted privilege
- **Wildcard tag values** — `has_tags: {k: '*'}` matches any value for tag `k` (presence check); concrete values match exactly
- **Privilege-securable compatibility** — filters incompatible privilege/securable combinations (e.g. `READ_VOLUME` only on volumes)
- **USE_CATALOG / USE_SCHEMA cascade** — when a grant policy matches a child securable and lists a USE privilege, the privilege is emitted against the correct parent ancestor (catalog for `USE_CATALOG`, schema for `USE_SCHEMA`) rather than being silently dropped by the compatibility filter. Bounded by policy scope: a schema-attached policy cannot cascade `USE_CATALOG` up to the catalog, and a table-attached policy cannot cascade either USE privilege onto its ancestors
- **Tagless policies** — policies with no tags grant directly to their attached securable
- **Policy expiry** — `expiry_date` field; expired policies are excluded from compilation
- **Privilege diffing** — computes grants and revokes by comparing desired vs actual state from `information_schema.*_privileges` system tables
- **Privilege execution** — generates and executes `GRANT`/`REVOKE` SQL

#### Principal management
- **Account SCIM proxy** (default) — fetches all account-level principals via `/api/2.0/account/scim/v2/` endpoints with pagination
- **Workspace SCIM** (optional `--use-workspace-scim`) — fetches workspace-level principals via SDK, automatically including the account-level system groups `account users` and `account admins` (which the workspace SCIM API does not surface)
- **Centralised resolution** — `PrincipalResolver` (in `uc_declarative_abac.principals`) bridges YAML display names with UC identifiers. Service principals appear in config by display name but in UC system tables / SDK responses as `application_id`; the resolver normalises both sides to the same `Principal` object so diffs compare correctly across all domains
- **Per-domain integration** — each domain's `compute_*_diff` accepts the shared `PrincipalResolver` and `ChangeLogger` and resolves principals internally on both desired and actual state before diffing
- **Runtime guards** — `ensure_resolved(p)` / `ensure_all_resolved(iterable)` assert the resolved invariant at the executor boundary before SQL emission
- **Unresolvable principals** — a principal in your **config** that can't be resolved (e.g. a mistyped group name) is a fatal error and fails the run. A principal that exists only in UC's **actual state** and can't be resolved from SCIM is dropped from the diff and reported as a non-fatal **warning** (the run still succeeds). This covers Databricks-managed **system/application service principals** — used internally by features like predictive optimization and scheduled dashboard refresh — which show up in the system tables as `application_id` UUIDs, are not returned by SCIM, and cannot be managed; they would otherwise cause intermittent failures whenever those background jobs have recently run.
- **Batch failure reporting** — unresolved principals in a single state object are aggregated into one `PrincipalValidationError` message listing every offender
- **Duplicate SP handling** — warns on duplicate service principal display names, errors if a duplicate SP is referenced in a policy

#### Pydantic model validation
- **`FunctionConfig`** — function definitions with `parameters` (list of `ParameterConfig`), `definition` (aliased as `return` in YAML), and tags rejection validator
- **`ParameterConfig`** — function parameters with automatic lowercase-to-uppercase `ColumnTypeName` coercion
- **Column owner rejection** — `ColumnConfig` rejects explicit `owner` field (always inherited from table)
- **Schema function support** — `SchemaConfig.functions` with parent name injection and duplicate detection
- **Mask/filter policy models** — `MaskPolicyConfig`, `FilterPolicyConfig` with optional `except`, optional `columns` (FILTER) and required non-empty `columns` (MASK)

#### Error handling
- **Error collection** — SQL execution errors and principal validation errors are collected (not raised immediately), allowing the pipeline to process as many operations as possible before reporting all failures
- **`ExecutionBatchError`** — raised at the end with all collected errors
- **Structured logging** — `Securables` / `Governed tags` / `Tags` / `Policies` / `Privileges` section headers, ordered by securable type then name, with dry-run prefix support and summary counts

#### Infrastructure
- **CLI** (`python -m uc_declarative_abac`) — required: `--config-dir`, `--warehouse-id`. Optional: `--profile` (CLI profile name from `~/.databrickscfg`; omit to use unified auth via env vars / default profile / metadata service — see the [Authentication](#authentication) section), `--dry-run`, `--use-workspace-scim`, the five opt-in mutation flags (`--enable-tag-management`, `--enable-taggable-management`, `--enable-taggable-creation`, `--enable-privilege-management`, `--enable-governed-tag-deletion`), their per-catalog scopes (`--manage-tags-for-catalogs`, `--manage-privileges-for-catalogs`, `--manage-taggables-for-catalogs`, `--create-taggables-for-catalogs` — each defaults to `*` and is a no-op unless its paired enable flag is set), and `--force` (skip interactive confirmations) — all described below.
- **GitHub Action** — reusable composite action at `deploy/action.yml`; caller repos invoke it as `liamperritt/uc-declarative-abac/deploy@<ref>` to reconcile their own YAML configs against UC on push / PR / schedule (see the [GitHub Action](#github-action) section)
- **Hybrid SQL polling** — `wait_timeout=50s` with `on_wait_timeout=CONTINUE` and 10s polling for long-running queries
- **External links** — fetches SQL results via external link URLs for large result sets
- **Parallel state fetch** — securables, tags, privileges, policies, governed tags, and principals are fetched concurrently
- **`information_schema` filtering** — all state queries exclude the `information_schema` schema and its child objects
- **Privileged-action opt-in flags** — five classes of mutation are gated behind explicit CLI flags. Each defaults to `false`; if unset, the corresponding actions are **skipped in both dry runs and real runs** — no fetch, no diff, no log section, no SQL. Pass the flag to opt in:
  - `--enable-tag-management` — create/update/remove tag assignments on securables. When off, the privileges compiler still honours grant-policy matches, but it matches against the *actual* on-disk UC tag state rather than the config's desired tags (since the engine is not going to apply the config's tags this run).
  - `--enable-taggable-management` — update attributes (`owner`, `comment`, and `rfa_destinations`) on existing taggable securables (catalogs, schemas, tables, volumes). Comment updates on a view's underlying table fail with a logged error (only view owners can update comment). Owner updates on tables whose `table_type` is `MATERIALIZED_VIEW` or `STREAMING_TABLE` fail with a logged error (change ownership on the pipeline instead). Function attributes are always engine-managed independently of this flag.
  - `--enable-taggable-creation` — create catalogs, schemas, tables, and volumes declared in config but absent from UC. Tables must declare ≥1 column with a `type` string on each (e.g. `type: STRING`); otherwise table creation fails with a `NonexistentSecurableError` explaining the requirement. `comment` and `location` declared on these objects are embedded directly in the `CREATE` statement: `MANAGED LOCATION '…'` for catalogs and schemas, `LOCATION '…'` on `CREATE TABLE` to make it external, and `CREATE EXTERNAL VOLUME … LOCATION '…'` for external volumes. Columns declared in config but missing from a pre-existing table are added via `ALTER TABLE … ADD COLUMN` as long as the column declares a `type`; columns without a `type` fail validation with a hint, just like the table case. By default (flag off), columns missing from a pre-existing table are surfaced as `NonexistentSecurableError` at dry-run, so drift is caught before any SQL runs.
  - `--enable-privilege-management` — grant/revoke privileges via `GRANT`/`REVOKE` SQL.
  - `--enable-governed-tag-deletion` — delete governed tags (account-level tag policies) that exist in UC but are absent from config. **High blast radius — deleting a tag policy orphans every object assigned that tag key across the account.** The engine logs the list of tags slated for deletion and requires an interactive `y`/`yes` confirmation at the terminal before issuing any `delete_tag_policy` call. UC itself decides what happens to objects that reference the deleted tag (typically: orphans them); the engine does not scan for references. Pair with `--force` in non-interactive contexts (see below).

  **Scoping filters for the four `--enable-...` flags above:**

  Each of the four management gates above (`tag`, `privilege`, `taggable-management`, `taggable-creation`) accepts a companion `--*-for-catalogs` flag that scopes the gate to a comma-separated list of catalog names. Each defaults to `'*'` (all configured catalogs). A filter is a no-op unless its paired `--enable-...` flag is also set. Unknown catalog names raise `ValueError` early. Function securables are never catalog-filtered — functions are engine-managed and flow through every scope.

  - `--manage-tags-for-catalogs <cat_a,cat_b>` — scope of `--enable-tag-management`. Out-of-scope catalog tag state is left untouched this run; for grant matching, the privileges compiler uses the UC actual tag state for out-of-scope catalogs.
  - `--manage-privileges-for-catalogs <cat_a,cat_b>` — scope of `--enable-privilege-management`. Grants/revokes are only emitted for in-scope catalogs.
  - `--manage-taggables-for-catalogs <cat_a,cat_b>` — scope of `--enable-taggable-management`. Non-function attribute updates (e.g. `owner`) are only emitted for in-scope catalogs.
  - `--create-taggables-for-catalogs <cat_a,cat_b>` — scope of `--enable-taggable-creation`. Out-of-scope missing securables surface as `NonexistentSecurableError` instead of being created.
  - `--retain-tag-prefixes <prefix_a,prefix_b>` — comma-separated tag-key prefixes the engine must never remove from securables, even when those tags are absent from config (it may still add/update them). Defaults to `class.`, so tags applied by UC's auto data classification (e.g. `class.phone_number`) are preserved across runs. Pass an empty string (`--retain-tag-prefixes ""`) to override the default and allow the engine to remove any unconfigured tag. No effect unless `--enable-tag-management` is set.

  **Auxiliary flag:**
  - `--force` — skip every interactive confirmation prompt and auto-confirm destructive actions. Required in non-interactive CI contexts (GitHub Actions, scripted runs) whenever a destructive gate like `--enable-governed-tag-deletion` is set; if the engine needs to prompt but stdin has no TTY, it aborts with `InteractiveConfirmationRequiredError` directing the user to set this flag. Scope is deliberately broad — future confirmation prompts (e.g. hypothetical securable deletion) will honour it without requiring a new flag.

  "Taggables" here means the securable types that support tagging: catalogs, schemas, tables, volumes, and columns. Functions aren't taggable and are managed separately.

---

*Declare governance in YAML. Version it. Deploy it.*
