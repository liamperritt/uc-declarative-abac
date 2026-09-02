# Finance governance — a worked `uc-abac` example

A complete, deployable-from-scratch governance project for a fictional financial-services
organisation. It models one logical catalog deployed to two environments and exercises
every GA feature of the [UC Declarative ABAC](../../README.md) engine while reading like a
real Unity Catalog setup. Every catalog, group, and governed tag is prefixed `uc_abac_`.

> **Deploy-from-scratch, no pre-existing principals.** The engine can create **groups** (it
> never creates users or service principals), so every principal in this project — owners,
> grant/mask/filter targets, tag assigners, group members — is a `uc_abac_*` **group** this
> project creates, or an always-present system group (`account users` / `account admins`).
> Leaf groups are created empty; you populate them with your real users afterwards (or from
> your IdP). Nothing here depends on a principal existing beforehand.

## What it deploys

- **Two catalogs from one definition:** `uc_abac_finance_prod` and `uc_abac_finance_uat`,
  both thin `$ref`s to a single catalog definition parameterised by `{{ env }}`.
- **A medallion layout per business sub-domain**, encoded in the schema name
  (`<sub_domain>_<medallion>`), never as a folder level:
  - **transactions** — a region-partitioned raw layer `transactions_bronze_amer` /
    `_emea` / `_apac` (one schema template instantiated three times) unioned into
    `transactions_silver` (which adds a `region` column for row filtering) and rolled up
    into `transactions_gold`.
  - **customers** — `customers_bronze` → `customers_silver` (PII masking) →
    `customers_gold` (a high-sensitivity `customer_360` masked by default).
  - **shared** — a utility schema holding the reusable governance UDFs.
- **A nested group hierarchy**, **governed tags** with allowed values and assigners, and
  **mask / filter / grant** ABAC policies.

> The engine declares the *structure and governance* of the medallion layers. Moving data
> between them (unioning bronze into silver, aggregating into gold) is your pipelines' job.

## Layout

The tree mirrors the Unity Catalog hierarchy — the only directory levels are UC resource
types (`catalogs/<catalog>/schemas/<schema>/{tables,volumes,functions}`). Business grouping
lives in the schema *name*, not the path.

```
configs/
├── definitions/
│   ├── catalogs/uc_abac_finance/
│   │   ├── uc_abac_finance.yaml            # the one catalog definition
│   │   └── schemas/
│   │       ├── base_schema/                # a reusable schema mixin, "extended" by silver/gold
│   │       ├── transactions_bronze/        # region template + one file per raw table + inline volumes
│   │       ├── transactions_silver/        # reuses the raw table defs, appends a region column
│   │       ├── transactions_gold/          # inline aggregate tables
│   │       ├── customers_bronze/ … _gold/
│   │       └── shared/                      # reusable UDFs (+ one inline UDF)
│   └── policies/                            # reusable policies, grouped by the tag they key on
│       ├── pii/  sensitivity/  region/  domain/  managed_by/
└── resources/
    ├── catalogs/                            # uc_abac_finance_prod.yaml, uc_abac_finance_uat.yaml
    ├── governed_tags/                       # one file per governed tag
    ├── groups/                              # one file per group
    └── schemas/                             # a standalone UAT-only sandbox schema
```

### When to use a separate file vs. inline

- **A definition reused across schemas gets its own file.** The raw transaction and customer
  tables live one-per-file under their bronze schema's `tables/` folder because the regional
  bronze schemas *and* silver all `$ref` them. The UDFs and policies are separate files for
  the same reason.
- **A definition nothing else uses is inlined.** The `*_gold` aggregate tables are written
  inline in their schema file; the bronze landing volumes are inlined in the bronze schema;
  one filter policy uses an inline function.

### Policies are grouped by tag

A policy file lives in the folder named for the governed tag it matches
(`pii/`, `sensitivity/`, `region/`, `domain/`, `managed_by/`), so you can find the rule that
governs a tag by looking in that tag's folder.

## Governed tags

| Tag | Values | Purpose |
|---|---|---|
| `uc_abac_pii` | name, email, phone, national_id, address | column masking |
| `uc_abac_classification` | public, internal, confidential, restricted | classification tier |
| `uc_abac_sensitivity` | low, medium, high | table/column sensitivity; drives secure-by-default masking + large-txn filter |
| `uc_abac_domain` | customer, account, transaction, aggregate | business domain of a schema/table |
| `uc_abac_layer` | bronze, silver, gold, shared | medallion layer of a schema |
| `uc_abac_region` | amer, emea, apac | region of a regional (bronze) schema; drives per-region grants |
| `uc_abac_region_column` | *(key-only)* | marks the silver `region` column for row filtering |
| `uc_abac_environment` | prod, uat | catalog environment (inherited to children) |
| `uc_abac_managed_by` | uc_declarative_abac | marks a catalog as governed by this project |

## Group hierarchy

All groups are created by this project (nested groups demonstrate membership features):

```
uc_abac_data_platform        → uc_abac_platform_engineers
uc_abac_data_governors       → uc_abac_data_stewards, uc_abac_compliance
uc_abac_pii_viewers          → uc_abac_fraud_analysts, uc_abac_compliance
uc_abac_finance_analysts_prod→ uc_abac_region_amer, _emea, _apac   (template, per env)
uc_abac_finance_analysts_uat → uc_abac_region_amer, _emea, _apac
uc_abac_temp_auditors        → uc_abac_compliance     (expires 2026-12-31: members removed)
```

Leaf groups (`uc_abac_platform_engineers`, `uc_abac_data_stewards`, `uc_abac_compliance`,
`uc_abac_fraud_analysts`, `uc_abac_region_*`) are created empty — add your real users.

## Features exercised

Definitions vs. resources · one catalog definition deployed to two environments · template
variables (`$vars` defaults + required, `{{ env }}` / `{{ region }}` in values, templated
principals, a schema template instantiated per region, a group template per environment) ·
extending a base schema via a root `$ref` · `$ref` deep-merge overrides (appending a column,
merging a column tag) · reusable + inline table/function/policy definitions · columns with
types, comments and tags · owners · RFA destinations (email + URL) · catalog vs. schema tags
(no duplication of inherited catalog tags) · governed tags with allowed values + assigners +
a key-only tag · a nested group hierarchy with an expiring group and a rename-ready `id` ·
**mask** policies (tag match, `has_none_of_tags`, a constant column, secure-by-default
MATCH-COLUMNS-TRUE, `has_any_of_tags` across keys) · **filter** policies (reusable + inline
functions, region row-level security, large-transaction oversight) · **grant** policies
(the `read`/`use`/`create` abstractions, concrete volume privileges, `all_privileges`,
`for: catalog/schema/volume`, the `use_catalog`/`use_schema` cascade, wildcard tag matches,
`expiry_date`) · a standalone resource schema consolidated into its catalog.

## Deploy it

### Prerequisites

The identity `uc-abac` authenticates as (typically a service principal) needs, per the
[main README](../../README.md#authentication): **workspace admin**, **metastore admin**,
governed-tag **creator/manager**, and — because this project creates groups — the group
scopes run against the **account SCIM proxy** (so don't combine them with workspace SCIM).

### Steps

```bash
# 1. Validate offline — no warehouse or credentials needed.
uc-abac validate --config-dir configs

# 2. Authenticate (env-based shown; a --profile also works).
export DATABRICKS_HOST=https://<workspace>.cloud.databricks.com
export DATABRICKS_TOKEN=<token>

# 3. Preview the plan. Run from this directory so uc_abac.yml is picked up;
#    supply the warehouse id (or set it in uc_abac.yml / UC_ABAC_WAREHOUSE_ID).
uc-abac deploy --warehouse-id <warehouse-id> --dry-run

# 4. Apply.
uc-abac deploy --warehouse-id <warehouse-id>
```

`uc_abac.yml` in this directory sets the scopes: additive tag/privilege/attribute management
and object + group creation are on; destructive gates (policy / governed-tag / group
deletion) are commented out — enable them deliberately, and add `--force` in CI.

### Continuous deployment

Copy `.github/workflows/*` into your own governance repo (they don't run from inside this
example). `validate-*` checks configs on every push; `deploy-*` dry-runs on PRs and applies
on merges to `main` and on a schedule. Set the `DATABRICKS_HOST` / `DATABRICKS_TOKEN` secrets
and the `DATABRICKS_WAREHOUSE_ID` variable.

## Use it as a starting point

Copy `finance_demo/` into a new repo, delete what you don't need, rename the
`uc_abac_finance` catalog and the `uc_abac_` prefixes to your own, point `uc_abac.yml` at your
warehouse, and iterate with `uc-abac validate`. Optional locations (managed catalog/schema,
external tables/volumes) are shown commented — enable them once you have a storage location.
