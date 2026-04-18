# UC ABAC Governor

The UC ABAC Governor lets Databricks customers define their Attribute-Based Access Control (ABAC) governance model via **declarative YAML files**. Define once, version in Git, and deploy to Unity Catalog—including as a **GitHub Action** from a repo containing your YAML configs.

## Overview

Instead of managing grants, tags, and policies manually in the Databricks workspace, you describe your ABAC governance model in YAML. The engine reads your configs, queries the UC system tables to determine the current state of deployed resources, computes a diff between the desired and actual state, and then applies only the changes required to bring UC in line with your configs.

Configs are split into two namespaces:

- **`definitions:`** — catalog-agnostic, reusable templates (schemas, tables, volumes, functions, ABAC policies).
- **`resources:`** — concrete, deployable instances (e.g., catalogs and their contents) that can compose definitions into real UC objects.

Definitions define *what* exists; resources define *where* it gets deployed.

> **Note:** Definitions are not mandatory. You can define all of your governance directly under `resources:` without using `definitions:` at all. Definitions exist to reduce config duplication when the same logical objects appear in multiple places — for example, an ABAC policy that is applied across many catalogs, schemas that are replicated across environment catalogs (dev, test, prod), or bronze tables that exist across multiple locale-based schemas.

## Quick Start

``python -m uc_abac_governor --config-dir tests/e2e/configs --warehouse-id 19460c3cc045a577 --use-workspace-scim --profile field-eng-east --dry-run``

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
| **Direct masking/filtering** | Table definitions with `filter` or column-level `mask` fields → engine applies the specified UC function directly to the table or column. |
| **UC objects** | Catalog resources compose schema, table, volume, and function definitions → engine creates/updates them in each target catalog. |

You maintain YAML as the source of truth; the engine turns it into UC objects and permissions.

## YAML Config Structures

Configs use **dictionaries keyed by definition IDs**. The recommended convention is to use `|`-delimited keys that mirror the Unity Catalog path of the object — e.g. `my_catalog` for a catalog, `my_catalog|sales` for a schema, `my_catalog|sales|orders` for a table. This matches the Databricks Terraform provider's composite resource IDs (e.g. `<metastore_id>|<name>` for UC connections). For reusable, catalog-agnostic definitions (typically policies and shared functions), a `<domain>|<name>` style works well — e.g. `abac|mask_pii`. The `|` delimiter is a convention only and is not enforced by the engine — keys can be any valid YAML string.

Key conventions by type:

| Type | Convention | Example |
|------|-----------|---------|
| catalogs | `<catalog_name>` | `operations` |
| schemas | `<catalog_name>\|<schema_name>` | `operations\|sales` |
| tables | `<catalog_name>\|<schema_name>\|<table_name>` | `operations\|sales\|orders` |
| volumes | `<catalog_name>\|<schema_name>\|<volume_name>` | `operations\|landing\|raw_events` |
| functions (catalog-specific) | `<catalog_name>\|<schema_name>\|<function_name>` | `operations\|shared\|mask_pii_email` |
| functions (cross-catalog, reusable) | `<domain>\|<function_name>` | `abac\|mask_pii` |
| policies (cross-catalog, reusable) | `<domain>\|<policy_name>` | `abac\|mask_pii_email` |

These keys are the stable identity for each entity and let you reference entities across files via `$defs/<type>/<key>` or `$ref: $defs/<type>/<key>` syntax (inspired by JSON Schema's `$defs` and `$ref` keywords) which also supports selective config overrides (see the **Overrides** section below).

Any definition type (catalogs, schemas, tables, volumes, functions, mask/filter policy) can be promoted to a concrete resource by placing it under `resources:` with a `$ref`/`$defs` reference to the definition. For catalogs this is the usual pattern — the catalog definition captures the shape, and a resource catalog references it. For leaf types (table, volume, function) you can also promote them directly when you need a single deployed instance outside of a catalog composition; these require `catalog_name`/`schema_name` to be set.

### Definitions

Definition configs are reusable templates for every UC object type — catalogs, schemas, tables, volumes, functions, and policies. The recommended pattern is to structure your definitions like the UC catalog itself: one top-level `catalog` definition that composes the schemas, policies, tags, and other catalog-level metadata, and then nested schema / table / volume / function definitions organised by catalog and schema. This keeps definitions close to the UC object they describe and makes the resource side of the config trivial — usually just a `$ref` to the catalog definition with a few overrides (e.g. a name change between prod and test environments).

Cross-catalog reusable definitions (typically ABAC policies and shared functions) can live outside the catalog tree under `definitions/policies/` or `definitions/functions/` and be `$ref`'d from multiple catalogs.

#### Catalog definitions

Catalog definitions capture the canonical shape of a catalog — its tags, owner, RFA destination, catalog-level policies, and the list of schemas it contains. Key convention: `<catalog_name>`. A catalog definition composes schemas and policies via `$ref`/`$defs` entries; a resource catalog then references the whole definition and overrides only what differs between environments (commonly just `name` and a few tags).

```yaml
# definitions/catalogs/operations_prod/operations_prod.yaml
definitions:
  catalogs:
    operations:
      name: operations
      comment: Operations catalog
      owner: data_platform_team
      rfa_destination: data-governance@company.com
      tags:
        env: prod
      policies:
        - $ref: $defs/policies/abac|grant_use_catalog
        - $ref: $defs/policies/abac|mask_pii_email
      schemas:
        - $ref: $defs/schemas/operations_prod|sales
        - $ref: $defs/schemas/operations_prod|landing

# resources/catalogs/operations_prod.yaml
resources:
  catalogs:
    operations_prod:
      $ref: $defs/catalogs/operations
      name: operations_prod
```

#### Schema definitions

Schema definitions capture the shape of a schema: name, comment, owner, tags, policies, and RFA. Key convention: `<catalog_name>|<schema_name>` (e.g. `operations|sales`, `operations|landing`). Each schema definition lists the **tables**, **volumes**, **functions**, and/or **policies** it contains as `$ref`/`$defs` entries. A catalog definition references which schemas to include; the engine creates each schema and its listed children inside the owning catalog.

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
        - $defs/policies/shared|grant_read_on_sales
      tables:
        - $defs/tables/operations|sales|orders

# definitions/people/schemas/hr/hr.yaml
definitions:
  schemas:
    people|hr:
      name: hr
      comment: HR data (restricted)
      owner: hr_analytics
      rfa_destination: hr-access@company.com
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
        - $ref: $defs/functions/platform|shared|mask_pii_email


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

Tables are defined in a flat dictionary under `definitions: tables:`. Key convention: `<logical_catalog/domain>|<schema_name>|<table_name>` (e.g. `operations|sales|orders`).

```yaml
# definitions/operations/schemas/sales/tables/orders.yaml
definitions:
  tables:
    operations|sales|orders:
      name: orders
      owner: sales_engineering
      tags:
        classification: internal
        sales: ~
      rfa_destination: sales-data@company.com
      policies:
        - $ref: $defs/policies/shared|mask_pii_email

# definitions/people/schemas/hr/tables/employees.yaml
definitions:
  tables:
    people|hr|employees:
      name: employees
      owner: hr_analytics_team
      filter: platform.shared.reports_to_current_user
      tags:
        people: ~
      columns:
        - name: employee_id
        - name: full_name
          mask: platform.shared.mask_pii_name
        - name: email
          mask: platform.shared.mask_pii_email
        - name: salary
          tags:
            classification: confidential
```

Table definitions support two approaches to row-level and column-level security:

1. **Directly applied functions** (shown above) — `filter` and `mask` specify a fully qualified UC function name (e.g. `platform.shared.reports_to_current_user`) that is applied directly to the table or column. This is an alternative to tag-based ABAC policies and gives you explicit, per-table/per-column control.
2. **Tag-based ABAC policies** — instead of specifying functions directly, you tag columns and tables and let policy definitions match against those tags to apply masking, filtering, and grants across all matching objects (see [policy definitions](#policy-definitions)).

Column-level fields:
- **`name`** — the column name (required).
- **`type`** — the column data type (optional). If provided and the table does not yet exist, the framework will attempt to create it as a managed table with the specified column types.
- **`tags`** — key-value or valueless tags applied to the column. These can be matched by ABAC policy definitions.
- **`mask`** — a fully- or partially-qualified UC function name to apply as a column mask directly.

Table-level fields (in addition to the common fields `name`, `comment`, `owner`, `tags`, `rfa_destination`):
- **`filter`** — a fully- or partially-qualified UC function name to apply as a row filter directly on the table.
- **`columns`** — list of column-level configurations (see above).
- **`policies`** — list of policy `$ref`/`$defs` entries or inline policies scoped to this table.

Note that the `comment` field is not supported for tables and columns due to current Unity Catalog view limitations.

#### Volume definitions

Volumes are defined under `definitions: volumes:`. Key convention: `<logical_catalog/domain>|<schema_name>|<volume_name>` (e.g. `platform|landing|raw_events`).

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

Functions are defined under `definitions: functions:`. Key convention: `<logical_catalog/domain>|<schema_name>|<function_name>` (e.g. `platform|shared|mask_pii_email`). ABAC policies can leverage these functions by referencing the function definition inline, or via the fully qualified UC function resource name.

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

ABAC policies are defined under `definitions: policies:`. Key convention: `<logical_catalog/domain>|<policy_name>` (e.g. `shared|mask_pii_email`). Three types:

- **`mask`** — applies a function to columns matching a tag; uses `to` / `except` to control who sees masked vs. unmasked data.
- **`filter`** — applies a row-filter function to tables matching a tag; uses `to` / `except` to control who is filtered.
- **`grant`** — assigns privileges on objects matching a tag to listed principals; supports `expiry_date`.

Policy fields:
- **`to`** — the principals the policy is applied to (e.g. who sees the masked value, who gets the row filter applied, or who receives the grant).
- **`except`** — (`mask` and `filter` types only) principals exempted from the policy. Exempted principals see the original unmasked data or unfiltered rows.
- **`has_tags`** — a tag-match block that scopes the policy to tagged objects (grants scope to securables within the attached level; masks/filters scope to tagged tables). AND semantics across multiple entries. See the paragraphs below the examples for the full per-type behaviour.
- **`columns`** — (`mask` and `filter` types only) an ordered list of column slots, each with an `alias` (a local name used to reference the column within this policy) and a `has_tags` block that selects the actual table column by tag. Every column in the list is passed as an argument to the `function` in declaration order, so the list must match the function's parameter signature. For **mask** polciies, the **first** column is the one the mask function is applied to (i.e. it becomes `ON COLUMN <alias>` in the generated SQL) and is also passed as the first argument to the function.
- **`privileges`** — (`grant` type only) the UC privileges to assign. Supported values: `select`, `modify`, `create_table`, `create_schema`, `create_function`, `create_volume`, `use_catalog`, `use_schema`, `read_volume`, `write_volume`, `execute`, `all_privileges`, `external_use_schema`, `manage`.
- **`expiry_date`** — (`grant` type only) ISO 8601 date (`YYYY-MM-DD`) after which the grant is automatically revoked.

```yaml
# definitions/shared/policies/mask_email_pii.yaml
definitions:
  policies:
    shared|mask_email_pii:
      name: mask_email_pii
      comment: Mask email PII from all users except account admins
      type: mask
      function: platform.abac.mask_email_pii
      to:
        - account_users
      except:
        - pii_viewers
      columns:
        - alias: email
          has_tags:
            pii: email

# definitions/shared/policies/mask_customer_name_pii.yaml
definitions:
  policies:
    shared|mask_retail_segment_customer_names_pii
      name: mask_retail_segment_customer_names_pii
      comment: Mask retail-segment customer names (not commercial-segment customer names) from all users except account admins
      type: mask
      function: platform.abac.mask_retail_segment_customer_names_pii
      to:
        - account_users
      except:
        - customer_pii_viewers
      has_tags:
        domain: customer
      columns:
        - alias: name
          has_tags:
            is_pii: 'true'
            class: name
        - alias: segment
          has_tags:
            segment: '*'

# definitions/shared/policies/filter_by_region.yaml
definitions:
  policies:
    shared|filter_trips_by_region:
      name: filter_trips_by_region
      comment: Users can only see high sensitivity trips to or from their region
      type: filter
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
        - account_users
      except:
        - account_admins
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

# definitions/shared/policies/grant_read_on_sales.yaml
definitions:
  policies:
    shared|grant_read_on_sales:
      name: grant_read_on_sales
      comment: Grant sales team access to sales data (until May 2026)
      type: grant
      privileges:
        - select
      to:
        - data_engineers
        - sales_team
        - sp_sales_job_runner
      has_tags:
        business_area: sales
      expiry_date: 2026-05-01
```

For **grant** policies attached at a given level, the optional `has_tags` property is scoped to match only the tagged objects within that level — a policy on a schema only matches the schema and the tables and volumes within that schema; a policy on a table only matches that table. If multiple tags are specified, the policy is only applied to objects that match **all** of the listed tags (AND semantics). Omitting the `has_tags` property for a **grant** policy applies the privileges directly on the object to which the policy is attached.

If a **mask** or **filter** policy specifies the optional `has_tags` property, this matches against tagged **tables** only. Use the mandatory `columns.[*].has_tags` to match against tagged columns that you want to use for row filtering logic, or that you want to apply column masking to. Similarly, if multiple tags are specified, the policy will only be applied to tables/columns that have **all** tags present (AND semantics). The values of the tagged column are passed as a single parameter to the specified function.

For mask and filter policies, the `function` property can either be the fully qualified name of an existing UC function (string), or an inline function definition. When defining an inline function, the function resource will be deployed into the same catalog and schema as the policy. If the policy is attached at the catalog level, then the inline function will be deployed to the `default` schema of that catalog. If this results in duplicate functions with identical names, the framework will raise an error.

### Resources

Resource configs are concrete, deployable instances (e.g., catalogs and their contents) that can compose definitions into real UC objects.

#### Governed Tags

Governed tags specify a tag name with a enforced set of allowed values. They are defined under `resources: governed_tags:` (not definitions) because they are account-level singletons—there is no catalog-scoped variant. The dictionary key is used as the tag name if `name` is not provided. All governed tags should exclusively be created through this framework.

- **`name`** — the governed tag key.
- **`comment`** — a human-readable description of the governed tag's purpose.
- **`allowed_values`** — the fixed list of values that can be assigned to this tag. ABAC policies reference these tag key-value pairs to determine which columns to mask, which rows to filter, or which objects to grant access on.
- **`allowed_principals`** — the list of principals who allowed to `ASSIGN` the tag to Unity Catalog objects. This can be useful for users to test tag assignments within `dev` catalogs that are not governed by this `uc_abac_governor` framework. It is not recommended to manually assign tags to UC objects that are governed by this framework, as this will result in those tags being blown away the next time that this framework runs.

```yaml
# resources/governed_tags/pii.yaml
resources:
  governed_tags:
    pii:
      name: pii
      comment: Personally identifiable information
      allowed_values:
        - name
        - address
        - drivers_license
      allowed_principals:
        - account_users

# resources/governed_tags/classification.yaml
resources:
  governed_tags:
    classification:
      name: classification
      comment: Data classification level
      allowed_values:
        - public
        - internal
        - confidential
        - restricted
      allowed_principals:
        - data_governance_team
        - john.smith@company.com
        - sp_data_governor
```

Once a tag policy is created, you can apply it to tables, columns, schemas, and other UC objects via the `tags:` field on any definition or resource. ABAC policies then match against these tag key-value pairs (e.g. `pii: email`, `classification: confidential`) to enforce masking, filtering, or grants.

#### Catalogs

Catalogs are deployed by placing an entry under `resources: catalogs:`. The recommended form is a thin `$ref` to a matching catalog definition — this keeps all the interesting composition (schemas, policies, tags) in the definition, and leaves the resource side as a one-line pointer. Overrides can be applied on the `$ref` entry when a resource needs to differ from its definition (for example, a test catalog that reuses a prod definition but changes `name`, a couple of tags, or a function reference).

**Pattern 1 — thin `$ref` with optional overrides.** One catalog definition, one matching resource:

```yaml
# definitions/catalogs/operations/operations.yaml
definitions:
  catalogs:
    operations:
      name: operations
      comment: Operations catalog
      owner: data_platform_team
      tags:
        env: prod
      policies:
        - $ref: $defs/policies/abac|mask_pii_email
      schemas:
        - $ref: $defs/schemas/operations_prod|sales
        - $ref: $defs/schemas/operations_prod|landing

# resources/catalogs/operations_prod.yaml
resources:
  catalogs:
    operations_prod:
      $ref: $defs/catalogs/operations
      name: operations_prod
```

**Pattern 3 — fully inline.** If you don't need reuse, skip the definition layer entirely and declare the catalog straight under `resources:`:

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
        - $ref: $defs/policies/abac|mask_pii_email
      schemas:
        - $ref: $defs/schemas/operations|sales
```

### Overrides

Any `$ref` entry can include additional fields alongside the reference. These fields override the corresponding values from the definition, letting you customise a single instance without modifying the shared definition. For example, you can override `owner`, `rfa_destination`, `comment`, `tags`, or `function` on a per-catalog or per-resource basis. Unspecified fields fall back to the definition.

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

> **Note:** Overrides replace top-level keys in their entirety — they do not merge into nested structures. For example, you cannot override a single tag; you must specify all tags. The same applies to `tables`, `volumes`, `functions`, and any other list or map field.

---

## File Organization

The recommended convention is to **mirror the Unity Catalog directory structure** under `definitions/catalogs/`, so each catalog/schema/table/volume/function config file sits where you'd expect to find it in UC. Cross-catalog reusable content (policies, shared functions) lives outside the catalog tree under `definitions/policies/` or `definitions/functions/`. The resource side stays thin — typically one file per catalog that `$ref`s the matching catalog definition.

Recommended layout (mirrors the structure used by the e2e tests in `tests/e2e/configs/`):

```
configs/
├── definitions/
│   ├── catalogs/
│   │   └── operations/
│   │       ├── operations.yaml         # catalog definition
│   │       └── schemas/
│   │           ├── sales/
│   │           │   ├── sales.yaml           # schema definition
│   │           │   ├── tables/
│   │           │   │   ├── orders.yaml      # table definition
│   │           │   │   └── quotes.yaml
│   │           │   └── functions/
│   │           │       └── lookup_region.yaml
│   │           └── landing/
│   │               ├── landing.yaml
│   │               └── volumes/
│   │                   └── raw_events.yaml
│   ├── policies/                            # cross-catalog reusable policies
│   │   ├── mask_pii.yaml
│   │   └── grant_catalog_read.yaml
│   └── functions/                           # cross-catalog reusable functions (optional)
│       └── mask_pii_email.yaml
└── resources/
    ├── catalogs/
    │   └── operations_prod.yaml             # thin $ref to the catalog definition
    └── governed_tags/
        └── pii.yaml
```

This folder structure is a recommendation, not enforced by the engine — the engine discovers every `.yaml` / `.yml` file under the config root and resolves references by definition key, not by file path. But keeping files where you'd expect them in a UC browser makes configs easy to navigate, and pairing each catalog definition with a matching one-line resource file is a clean split: **definitions describe what exists; resources describe where it gets deployed.**

## Deployment

The engine is designed to run in CI/CD. You can use it as a **GitHub Action** on a repository that holds your YAML files: on push or on a schedule, the action runs the engine against your configs and **declaratively deploys ABAC governance** to your Databricks workspace and Unity Catalog.

It is recommended to run the deployment whenever a new version of your YAML files is released, as well as running a scheduled deployment at least once per day (to reduce drift and to ensure features like the grant policy `expiry_date` work as intended).

> **Note:** By default, the engine assumes that securables (catalogs, schemas, tables, volumes) already exist in Unity Catalog and will only manage tags, grants, and policies on them. If you want the engine to create securables that don't exist yet, pass the `--create-if-not-exists` flag.

### Deployment semantics

Not all object types are managed the same way:

| Category | Behaviour | Examples |
|----------|-----------|----------|
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

#### Securables domain
- **Owner management** — detects owner drift between config and workspace; updates via WorkspaceClient API for all securable types (catalogs, schemas, tables, volumes, functions)
- **Function creation** — creates new functions via `CREATE FUNCTION` SQL with parameters and return expression (no `RETURNS` clause; UC infers the type)
- **Function replacement** — replaces existing functions whose parameters or definition have changed via `CREATE OR REPLACE FUNCTION` SQL
- **Polymorphic securable state** — `Securable` base class with `Function` subclass; executor dispatches via structural pattern matching (`match`/`case`), extensible for future securable types
- **Generic attribute updates** — `AttributeUpdate` type supports any attribute (currently `owner`); adding future attributes (comment, RFA destination) requires only adding a field to `SecurableAttributes` and a dispatch branch in the executor
- **Single state query** — `fetch_actual_securables` combines attributes and function definitions in one UNION ALL query with `collect_list`/`sort_array`/`transform` aggregation for parameters

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
- **Wildcard tag values** — `has_tags: {k: '*'}` matches any value for tag `k` (presence check); concrete values match exactly
- **Privilege-securable compatibility** — filters incompatible privilege/securable combinations (e.g. `READ_VOLUME` only on volumes)
- **Tagless policies** — policies with no tags grant directly to their attached securable
- **Policy expiry** — `expiry_date` field; expired policies are excluded from compilation
- **Privilege diffing** — computes grants and revokes by comparing desired vs actual state from `information_schema.*_privileges` system tables
- **Privilege execution** — generates and executes `GRANT`/`REVOKE` SQL

#### Principal management
- **Account SCIM proxy** (default) — fetches all account-level principals via `/api/2.0/account/scim/v2/` endpoints with pagination
- **Workspace SCIM** (optional `--use-workspace-scim`) — fetches workspace-level principals via SDK
- **Centralised resolution** — `PrincipalResolver` (in `uc_abac_governor.principals`) bridges YAML display names with UC identifiers. Service principals appear in config by display name but in UC system tables / SDK responses as `application_id`; the resolver normalises both sides to the same `Principal` object so diffs compare correctly across all domains
- **Per-domain integration** — each domain's `compute_*_diff` accepts the shared `PrincipalResolver` and `ChangeLogger` and resolves principals internally on both desired and actual state before diffing
- **Runtime guards** — `ensure_resolved(p)` / `ensure_all_resolved(iterable)` assert the resolved invariant at the executor boundary before SQL emission
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
- **Structured logging** — `Securables` / `Tags` / `Policies` / `Privileges` section headers, ordered by securable type then name, with dry-run prefix support and summary counts

#### Infrastructure
- **CLI** (`python -m uc_abac_governor`) — `--config-dir`, `--warehouse-id`, `--profile`, `--dry-run`, `--use-workspace-scim`
- **Hybrid SQL polling** — `wait_timeout=50s` with `on_wait_timeout=CONTINUE` and 10s polling for long-running queries
- **External links** — fetches SQL results via external link URLs for large result sets
- **Parallel state fetch** — securables, tags, privileges, policies, and principals are fetched concurrently
- **`information_schema` filtering** — all state queries exclude the `information_schema` schema and its child objects

### Not yet implemented

- **Governed tags** — `resources.governed_tags` with `allowed_values`, `allowed_principals`, `comment` (documented in README but not built)
- **UC object creation** — creating/updating catalogs, schemas, tables, volumes (functions are supported; other securable types require adding `Securable` subclasses)
- **Object attributes** — `comment`, `rfa_destination` on securables (the `owner` attribute is implemented; adding new attributes requires only a field on `SecurableAttributes` and an executor dispatch branch)
- **Direct mask/filter** — `filter` on tables and `mask` on columns (non-ABAC, directly applied functions)
- **Abstracted privilege names** — `read`, `edit`, `create` expanding to multiple UC privileges
- **GitHub Action** — CI/CD deployment action

---

*Define governance in YAML. Version it. Deploy it.*
