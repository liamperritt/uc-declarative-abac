# UC ABAC Governor

The UC ABAC Governor lets Databricks customers define their Attribute-Based Access Control (ABAC) governance rules and mappings via **declarative YAML files**. Define once, version in Git, and deploy to Unity Catalog—including as a **GitHub Action** from a repo containing your YAML configs.

## Overview

Instead of managing grants, tags, and policies manually in the Databricks workspace, you describe your ABAC governance model in YAML. The engine reads your configs, queries the UC system tables to determine the current state of deployed resources, computes a diff between the desired and actual state, and then applies only the changes required to bring UC in line with your configs.

Configs are split into two namespaces:

- **`definitions:`** — catalog-agnostic, reusable templates (schemas, tables, volumes, functions, policies).
- **`resources:`** — concrete, deployable instances (e.g., catalogs and their contents) that can compose definitions into real UC objects.

Definitions define *what* exists; resources define *where* it gets deployed.

## What You Can Define in YAML

### Definitions (catalog-agnostic templates)

- **Schema definitions** — catalog-agnostic schema templates listing their child tables, volumes, and functions.
- **Table definitions** — table definitions tied to a schema definition.
- **Volume definitions** — volume definitions tied to a schema definition.
- **Function definitions** — UDF definitions with parameters and return expressions.
- **Policy definitions** — ABAC policies for column masking, row filtering, and grants.

### Resources (deployed UC objects)

- **Governed tags** — UC governed tags with allowed values, owners, and comments.
- **Catalogs** — compose schema and policy definitions into deployable units, with per-catalog overrides.
- **Schemas, tables, volumes, functions, mask/filter policies** — concrete instances that can reference relevant definitions.

### Metadata on all objects

- **Owners** — set or update owners on catalogs, schemas, tables, volumes, and functions.
- **Comments** — manage descriptions on UC objects.
- **Tags** — key-value or valueless tags (using `~`) applied to any object.
- **RFA destinations** — configure where access requests are sent for governed objects.

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

Configs use **dictionaries keyed by definition IDs**. The recommended convention is to use `|`-delimited keys (e.g. `operations|sales`, `operations|sales|orders`, `platform|shared|mask_pii_email`), following the same pattern as the Databricks Terraform provider which uses `|` for composite resource IDs (e.g. `<metastore_id>|<name>` for UC connections). However, the `|` delimiter is a convention only and is not enforced by the engine — keys can be any valid YAML string. These keys are the stable identity for each entity and let you reference entities across files via `$ref: $defs/<type>/<key>` syntax (inspired by JSON Schema's `$defs` and `$ref` keywords).

The `name` field determines the unqualified object name created in Databricks/Unity Catalog. For resources, `name` is optional — if omitted, the dictionary key is used as the name (e.g. a governed tag keyed `pii` with no name specified will be created with the name `pii`).

Any definition type (schemas, tables, volumes, functions, mask/filter policy) can be promoted to a concrete resource by placing it under `resources:` with a `$ref` to the definition and a fixed `catalog`/`schema`. This is useful when you need a specific deployed instance outside of a catalog composition.

### Overrides

Any `$ref` entry can include additional fields alongside the reference. These fields override the corresponding values from the definition, letting you customise a single instance without modifying the shared definition. For example, you can override `owner`, `rfa_destination`, `comment`, `tags`, or `function` on a per-catalog or per-resource basis. Unspecified fields fall back to the definition.

Overrides also support recursive references — you can nest `$ref` entries within an override to further customise child objects. For example, overriding a schema's `tables` list with specific table references that themselves carry overrides:

```yaml
resources:
  catalogs:
    operations_test:
      comment: TEST Operations catalog
      schemas:
        - $ref: $defs/schemas/operations|sales
          name: sales_staging
          tables:
            - $ref: $defs/tables/operations|sales|orders
            - $ref: $defs/tables/operations|sales|quotes
              comment: This table only exists in TEST
```

### Definitions

Definition configs are catalog-agnostic, reusable templates (schemas, tables, volumes, functions, policies).

#### Schema definitions

Schema definitions are catalog-agnostic templates: name, comment, owner, tags, and RFA. Key convention: `<domain>|<schema_name>` (e.g. `operations|sales`, `people|hr`). Each schema definition lists the **tables**, **volumes**, and/or **functions** it contains as `$ref` entries. Catalogs reference which schema definitions to instantiate; the engine creates each schema and its listed children in every catalog that includes it.

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
      tables:
        - $ref: $defs/tables/operations|sales|orders
          rfa_destination: sales-data2@company.com

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
          owner: hr_engineers

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
      catalog: platform_prod

# resources/catalogs/platform_test/schemas/shared/shared.yaml
resources:
  schemas:
    platform|shared_test:
      $ref: $defs/schemas/platform|shared
      catalog: platform_test
```

#### Table definitions

Tables are defined in a flat dictionary under `definitions: tables:`. Key convention: `<logical_catalog/domain>|<schema_name>|<table_name>` (e.g. `operations|sales|orders`).

```yaml
# definitions/operations/schemas/sales/tables/orders.yaml
definitions:
  tables:
    operations|sales|orders:
      name: orders
      comment: Customer order fact table
      owner: sales_engineering
      tags:
        classification: internal
        sales: ~
      rfa_destination: sales-data@company.com

# definitions/people/schemas/hr/tables/employees.yaml
definitions:
  tables:
    people|hr|employees:
      name: employees
      comment: Employee master data
      owner: hr_analytics_team
      filter: platform.shared.reports_to_current_user
      tags:
        people: ~
      columns:
        - name: employee_id
          comment: Unique employee identifier
        - name: full_name
          comment: Employee full name
          mask: platform.shared.mask_pii_name
        - name: email
          comment: Corporate email address
          mask: platform.shared.mask_pii_email
        - name: salary
          comment: Annual base salary
          tags:
            classification: confidential
```

Table definitions support two approaches to row-level and column-level security:

1. **Directly applied functions** (shown above) — `filter` and `mask` specify a fully qualified UC function name (e.g. `platform.abac.is_not_eu_region`) that is applied directly to the table or column. This is an alternative to tag-based ABAC policies and gives you explicit, per-table/per-column control.
2. **Tag-based ABAC policies** — instead of specifying functions directly, you tag columns and tables and let policy definitions match against those tags to apply masking, filtering, and grants across all matching objects (see [policy definitions](#policy-definitions)).

Column-level fields:
- **`name`** — the column name (required).
- **`type`** — the column data type (optional). If provided and the table does not yet exist, the framework will attempt to create it as a managed table with the specified column types.
- **`comment`** — description of the column.
- **`tags`** — key-value or valueless tags applied to the column. These can be matched by ABAC policy definitions.
- **`mask`** — a fully- or partially-qualified UC function name to apply as a column mask directly.

Table-level fields (in addition to the common fields `name`, `comment`, `owner`, `tags`, `rfa_destination`):
- **`filter`** — a fully- or partially-qualified UC function name to apply as a row filter directly on the table.
- **`columns`** — list of column-level configurations (see above).

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
      catalog: platform_prod
```

#### function definitions

Functions are defined under `definitions: functions:`. Key convention: `<logical_catalog/domain>|<schema_name>|<function_name>` (e.g. `platform|shared|mask_pii_email`). Policy definitions point to these functions by their fully qualified UC name.

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
```

#### Policy definitions

Policies are defined under `definitions: policies:`. Key convention: `<logical_catalog/domain>|<policy_name>` (e.g. `shared|mask_pii_email`). Three types:

- **`mask`** — applies a function to columns matching a tag; uses `to` / `except` to control who sees masked vs. unmasked data.
- **`filter`** — applies a row-filter function to tables matching a tag; uses `to` / `except` to control who is filtered.
- **`grant`** — assigns privileges on objects matching a tag to listed principals; supports `expiry_date`.

Policy fields:
- **`to`** — the principals the policy is applied to (e.g. who sees the masked value, who gets the row filter applied, or who receives the grant).
- **`except`** — principals exempted from the policy (applicable to `mask` and `filter` types only). Exempted principals see the original unmasked data or unfiltered rows.
- **`privileges`** — (`grant` type only) the UC privileges to assign. Supported values: `select`, `modify`, `create_table`, `create_schema`, `create_function`, `create_volume`, `use_catalog`, `use_schema`, `read_files`, `write_files`, `all_privileges`.
- **`expiry_date`** — (`grant` type only) ISO 8601 date (`YYYY-MM-DD`) after which the grant is automatically revoked.

```yaml
# definitions/shared/policies/mask_pii_email.yaml
definitions:
  policies:
    shared|mask_pii_email:
      name: mask_pii_email
      comment: Mask PII email data from all users except account admins
      type: mask
      function: platform.abac.mask_pii_email
      to:
        - account_users
      except:
        - account_admins
      tags:
        pii: email

# definitions/shared/policies/filter_out_eu_customers.yaml
definitions:
  policies:
    shared|filter_out_eu_customers:
      name: filter_out_eu_customers
      comment: Hide EU customer data from all users
      type: filter
      function: platform.abac.is_not_eu_region
      to:
        - account_users
      tags:
        region: ~

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
      tags:
        sales: ~
      expiry_date: 2026-05-01
```

If a policy specifies multiple tags, the policy is only applied to objects that match **all** of the listed tags (AND semantics). For example, a policy with `tags: { pii: email, classification: confidential }` would only apply to objects tagged with both `pii: email` and `classification: confidential`.

Policy definitions are catalog-agnostic. Catalogs reference which policies to apply via `$ref` entries, and can override fields (e.g. `function`) per catalog.

### Resources

Resource configs are concrete, deployable instances (e.g., catalogs and their contents) that can compose definitions into real UC objects.

#### Governed tags

Governed tags are Unity Catalog tag keys with a controlled set of allowed values. They are defined under `resources: governed_tags:` (not definitions) because they are account-level singletons—there is no catalog-scoped variant. The dictionary key is the tag key name as it will appear in Unity Catalog.

- **`allowed_values`** — the fixed list of values that can be assigned to this tag. Policies reference these tag key-value pairs to determine which columns to mask, which rows to filter, or which objects to grant access on.
- **`owner`** — the principal (user or service principal) who can manage the governed tag.
- **`comment`** — a human-readable description of the tag's purpose.

```yaml
# resources/governed_tags/pii.yaml
resources:
  governed_tags:
    pii:
      comment: Personally identifiable information
      owner: sp_data_governor
      allowed_values:
        - name
        - address
        - drivers_license

# resources/governed_tags/classification.yaml
resources:
  governed_tags:
    classification:
      comment: Data classification level
      owner: sp_data_governor
      allowed_values:
        - public
        - internal
        - confidential
        - restricted
```

Once a governed tag is created, you can apply it to tables, columns, schemas, and other UC objects via the `tags:` field on any definition or resource. Policies then match against these tag key-value pairs (e.g. `pii: email`, `classification: confidential`) to enforce masking, filtering, or grants.

#### Catalogs

Catalogs are defined under `resources: catalogs:` and compose schema definitions and policy definitions into a deployable unit. Each catalog lists the schemas to instantiate and the policies to apply, with optional per-catalog overrides on any `$ref` entry.

```yaml
# resources/catalogs/operations/operations_prod.yaml
resources:
  catalogs:
    operations_prod:
      comment: Production operations catalog
      owner: data_platform_team
      rfa_destination: data-governance@company.com
      tags:
        operations: ~
        env: prod
      policies:
        - $ref: $defs/policies/shared|mask_pii_email
      schemas:
        - $ref: $defs/schemas/operations|sales
          tables:
            - $ref: $defs/tables/operations|sales|orders
            - $ref: $defs/tables/operations|sales|quotes
        - $ref: $defs/schemas/people|hr
        - $ref: $defs/schemas/platform|landing

# resources/catalogs/operations/operations_test.yaml
resources:
  catalogs:
    operations_test:
      comment: Test operations catalog
      owner: data_platform_team
      rfa_destination: data-governance@company.com
      tags:
        operations: ~
        env: test
      policies:
        - $ref: $defs/policies/shared|mask_pii_email
          function: test_analytics.abac.mask_pii_email
      schemas:
        - $ref: $defs/schemas/operations|sales
        - $ref: $defs/schemas/people|hr
        - $ref: $defs/schemas/platform|landing
        - $ref: $defs/schemas/platform|shared
          owner: sp_test_job_runner
```

---

## File Organization

The recommended convention is to place your YAML configs under two top-level directories:

- **`definitions/`** — catalog-agnostic templates organised by domain (e.g. `definitions/operations/schemas/sales/`).
- **`resources/`** — concrete deployable instances organised by catalog (e.g. `resources/catalogs/operations/`).

This folder structure is not enforced by the engine — you can organise files however you like. The engine discovers all YAML files regardless of directory layout and resolves `$ref` entries by definition key, not by file path.

## Deployment

The engine is designed to run in CI/CD. You can use it as a **GitHub Action** on a repository that holds your YAML files: on push or on a schedule, the action runs the engine against your configs and **declaratively deploys ABAC governance** to your Databricks workspace and Unity Catalog.

### Deployment semantics

Not all object types are managed the same way:

| Category | Behaviour | Examples |
|----------|-----------|----------|
| **UC objects & attributes** | Additive only (create/update, never deletes) | Catalogs, schemas, tables, volumes, functions, comments |
| **Tags & grant policies** | Additive + removals/revokes | Tag assignments on objects, `GRANT` statements |
| **Mask & filter policies** | Additive only (create/update) | Column masking policies, row filter policies |

Mask and filter policies are currently additive-only because Unity Catalog does not yet expose a system table to track existing mask/filter policy assignments. Once UC adds this capability, the engine will handle removals for these policy types as well, matching the behaviour of tags and grants.

---

*Define governance in YAML. Version it. Deploy it.*
