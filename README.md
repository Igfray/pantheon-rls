# pantheon-rls

[![tests](https://github.com/Igfray/pantheon-rls/actions/workflows/ci.yml/badge.svg)](https://github.com/Igfray/pantheon-rls/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/pantheon-rls?color=blue&logo=pypi&logoColor=white)](https://pypi.org/project/pantheon-rls/)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://pypi.org/project/pantheon-rls/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

**Tenant isolation as a Postgres *guarantee* — force-RLS + least-privilege grants, as reusable SQL.** Zero required dependencies.

> The guarantee: tenant A cannot read or write tenant B's rows — enforced by the **database**, not by a `WHERE tenant_id = ?` you have to remember on every query. Forget one query and you leak; with this, the boundary is in the engine, below the app.

Extracted from [PANTHEON](https://pantheonlabs.co.uk), a multi-tenant AI substrate, where it's the isolation boundary under every scoped table. Companion to [pantheon-credit-ledger](https://github.com/Igfray/pantheon-credit-ledger) (which uses exactly this).

## What it does

Three statements per scoped table make isolation real:

```python
from pantheon_rls import enable_rls_sql, grant_crud_sql, bind_tenant

# 1. Once, in your migration, as the privileged (table-owning) role:
for stmt in enable_rls_sql("invoices"):
    conn.execute(stmt)
conn.execute(grant_crud_sql("invoices", "app_role"))   # your NON-superuser runtime role

# 2. Per request, on your app connection:
bind_tenant(session, tenant_id)   # every statement after this sees only this tenant's rows
```

`enable_rls_sql` emits `ENABLE` + **`FORCE`** row-level security + a fail-closed policy:

```sql
ALTER TABLE invoices ENABLE ROW LEVEL SECURITY;
ALTER TABLE invoices FORCE ROW LEVEL SECURITY;
CREATE POLICY invoices_tenant_isolation ON invoices
  USING      (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);
```

## The two things people get wrong

- **`FORCE`, not just `ENABLE`.** Without `FORCE`, the **table owner** bypasses the policy — so your migration/maintenance connection (and often your app, if it owns the tables) silently sees everything. `FORCE` subjects the owner too.
- **A superuser / `BYPASSRLS` role ignores RLS entirely.** So the app must connect at runtime as a **`NOSUPERUSER NOBYPASSRLS`** role; migrations use the privileged one. Miss this and every dev box (usually superuser) looks perfectly isolated while production leaks. `grant_crud_sql` exists to point the four CRUD verbs at that non-privileged role.

And it's **fail-closed**: `current_setting(name, true)` is `NULL` when unset, `NULLIF` maps `''` → `NULL`, and `col = NULL` is never true — so *no tenant context means zero rows*, never "all rows".

## Safe to call with non-constant identifiers

Table / column / role / GUC names are validated to be plain `[schema.]identifiers` (anything else raises `ValueError`), and the tenant id at bind time is passed as a **bind parameter**, never interpolated — so these helpers don't become a SQL-injection vector even if a name comes from config.

## Install

```bash
pip install pantheon-rls                 # SQL helpers only, zero dependencies
pip install "pantheon-rls[sqlalchemy]"   # + bind_tenant() convenience (else run set_config with your own driver)
# or copy the single pantheon_rls.py file
```

## Scope

This is the isolation **primitive** — the RLS DDL + grant helpers + the per-transaction tenant bind. It is not an ORM, a migration tool, or a full multi-tenancy framework; it's the ~60 lines that make Postgres itself refuse cross-tenant access, done right (FORCE + non-privileged role + fail-closed).


## Changelog

- **0.1.1** — **identifiers are now double-quoted** in the emitted DDL, so a reserved-word table or role (`order`, `user`) is valid SQL instead of a syntax error. Validation is unchanged (it already forbids the `"` needed to break out — quoting is not the injection guard, it just makes reserved words work). Names are quoted verbatim, so pass identifiers in the exact case they exist.
- **0.1.0** — initial release.

## License

Apache-2.0. See `LICENSE`.
