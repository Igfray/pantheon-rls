# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Isaac Teague Frayling
"""Tenant isolation as a Postgres GUARANTEE — force-RLS + least-privilege grants, as reusable SQL.

Multi-tenant isolation that lives in application code (`... WHERE tenant_id = ?` on every query) is only as
strong as the one query someone forgets. This puts the boundary in the DATABASE, where a bug in app code
cannot cross it. Three things make it real, per scoped table:

  1. ENABLE ROW LEVEL SECURITY  — policies apply to the table.
  2. FORCE ROW LEVEL SECURITY   — they apply even to the TABLE OWNER, so a migration / maintenance connection
                                  is subject too (without FORCE, the owner silently bypasses the policy).
  3. a policy keyed on a session variable — USING + WITH CHECK compare the tenant column against
                                  `current_setting('app.current_tenant')`, which the app binds per transaction.

Fail-closed by construction: `current_setting(name, true)` is NULL when unset, NULLIF maps '' -> NULL, and
`col = NULL` is never true — so NO tenant context means ZERO rows, never "all rows".

THE FOOTGUN (why FORCE + a non-privileged role matter): a Postgres SUPERUSER or any BYPASSRLS role ignores
every policy. So the app must connect at runtime as a NOSUPERUSER / NOBYPASSRLS role; migrations use the
privileged role. Connect as a superuser at runtime and you silently see everything — while every dev box
(usually superuser) looks perfectly isolated. Getting this right is the difference between a demo and something
you would run.

Identifiers (table / column / role / GUC) are validated to be plain names, so these helpers are safe to call
with values that aren't hard-coded. Values (the tenant id at bind time) are passed as bind parameters, never
interpolated. Extracted from PANTHEON (a multi-tenant AI substrate), where this is the isolation boundary under
every scoped table.

    from pantheon_rls import enable_rls_sql, grant_crud_sql, bind_tenant
    for stmt in enable_rls_sql("invoices"):     # once, in your migration, as the privileged role
        conn.execute(stmt)
    conn.execute(grant_crud_sql("invoices", "app_role"))   # your NON-superuser runtime role
    bind_tenant(session, tenant_id)             # per request; everything after sees only this tenant's rows
"""
from __future__ import annotations

import re

DEFAULT_TENANT_GUC = "app.current_tenant"
POLICY_SUFFIX = "tenant_isolation"

_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?$")   # [schema.]name
_GUC_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*$")        # class.name custom GUC
_TYPE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_ ]*$")                              # uuid / text / bigint / ...


def _ident(name: str, what: str) -> str:
    if not isinstance(name, str) or not _IDENT_RE.match(name):
        raise ValueError(f"unsafe SQL {what} {name!r}: expected a plain [schema.]identifier")
    return name


def _guc(name: str) -> str:
    if not isinstance(name, str) or not _GUC_RE.match(name):
        raise ValueError(f"unsafe GUC name {name!r}: expected a 'class.name' setting")
    return name


def _tenant_expr(tenant_guc: str, tenant_type: str | None) -> str:
    cast = ""
    if tenant_type:
        if not _TYPE_RE.match(tenant_type):
            raise ValueError(f"unsafe type {tenant_type!r}")
        cast = f"::{tenant_type.strip()}"
    return f"NULLIF(current_setting('{_guc(tenant_guc)}', true), ''){cast}"


def _policy(table: str) -> str:
    return f"{table.replace('.', '_')}_{POLICY_SUFFIX}"


def enable_rls_sql(table: str, *, tenant_column: str = "tenant_id",
                   tenant_guc: str = DEFAULT_TENANT_GUC, tenant_type: str | None = "uuid") -> list[str]:
    """The DDL that places `table` fully under tenant isolation (ENABLE + FORCE + a fail-closed policy). Run once
    per scoped table in your migration, as the table-owning / privileged role. `tenant_type=None` for no cast."""
    t = _ident(table, "table")
    col = _ident(tenant_column, "tenant_column")
    expr = _tenant_expr(tenant_guc, tenant_type)
    policy = _policy(t)
    return [
        f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY;",
        f"ALTER TABLE {t} FORCE ROW LEVEL SECURITY;",
        f"DROP POLICY IF EXISTS {policy} ON {t};",
        f"CREATE POLICY {policy} ON {t} USING ({col} = {expr}) WITH CHECK ({col} = {expr});",
    ]


def disable_rls_sql(table: str) -> list[str]:
    """Reverse `enable_rls_sql` (drop the policy, unforce, disable)."""
    t = _ident(table, "table")
    policy = _policy(t)
    return [
        f"DROP POLICY IF EXISTS {policy} ON {t};",
        f"ALTER TABLE {t} NO FORCE ROW LEVEL SECURITY;",
        f"ALTER TABLE {t} DISABLE ROW LEVEL SECURITY;",
    ]


def grant_crud_sql(table: str, role: str) -> str:
    """GRANT the four CRUD verbs on `table` to `role` — point this at your NON-superuser, NON-BYPASSRLS app role
    (the one the runtime connects as), never a superuser (which ignores RLS)."""
    return f"GRANT SELECT, INSERT, UPDATE, DELETE ON {_ident(table, 'table')} TO {_ident(role, 'role')};"


def bind_tenant(session, tenant_id, *, tenant_guc: str = DEFAULT_TENANT_GUC) -> None:
    """Bind the tenant GUC for the CURRENT transaction (local=true) on a SQLAlchemy session — call at the start
    of each request; every statement after sees only this tenant's rows. The value is a BIND PARAMETER, never
    interpolated. (Needs SQLAlchemy: `pip install pantheon-rls[sqlalchemy]`. Non-SQLAlchemy callers can run
    `SELECT set_config('app.current_tenant', <tenant>, true)` with their own driver.)"""
    from sqlalchemy import text
    session.execute(text("SELECT set_config(:guc, :val, true)"),
                    {"guc": _guc(tenant_guc), "val": str(tenant_id)})
