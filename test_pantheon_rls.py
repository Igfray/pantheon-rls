# SPDX-License-Identifier: Apache-2.0
import pytest
from pantheon_rls import bind_tenant, disable_rls_sql, enable_rls_sql, grant_crud_sql


def test_enable_shape_and_fail_closed():
    sql = "\n".join(enable_rls_sql("invoices"))
    assert "ALTER TABLE invoices ENABLE ROW LEVEL SECURITY;" in sql
    assert "ALTER TABLE invoices FORCE ROW LEVEL SECURITY;" in sql          # FORCE = owner subject too
    assert "CREATE POLICY invoices_tenant_isolation ON invoices" in sql
    # fail-closed: unset GUC -> NULL -> no rows
    assert "tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid" in sql


def test_configurable_column_guc_type():
    sql = "\n".join(enable_rls_sql("acct", tenant_column="org_id",
                                   tenant_guc="app.current_org", tenant_type="text"))
    assert "org_id = NULLIF(current_setting('app.current_org', true), '')::text" in sql
    assert "::uuid" not in sql


def test_no_cast_when_type_none():
    assert "::" not in "\n".join(enable_rls_sql("t", tenant_type=None)).split("current_setting")[1]


def test_disable_and_grant():
    assert any("DISABLE ROW LEVEL SECURITY" in s for s in disable_rls_sql("t"))
    assert grant_crud_sql("t", "app_role") == "GRANT SELECT, INSERT, UPDATE, DELETE ON t TO app_role;"


def test_schema_qualified_allowed():
    assert enable_rls_sql("public.invoices")[0].startswith("ALTER TABLE public.invoices")


@pytest.mark.parametrize("bad", ["users; DROP TABLE x", "users--", "a b", "1users", "users)", "'; --", "a.b.c"])
def test_identifier_injection_rejected(bad):
    with pytest.raises(ValueError):
        enable_rls_sql(bad)
    with pytest.raises(ValueError):
        grant_crud_sql("t", bad)


def test_bad_guc_and_type_rejected():
    with pytest.raises(ValueError):
        enable_rls_sql("t", tenant_guc="app.current'; --")
    with pytest.raises(ValueError):
        enable_rls_sql("t", tenant_type="uuid; DROP")


def test_bind_tenant_passes_value_as_bind_param():
    seen = {}

    class FakeSession:
        def execute(self, stmt, params=None):
            seen["sql"] = str(stmt); seen["params"] = params

    bind_tenant(FakeSession(), "tenant-123")
    assert seen["params"] == {"guc": "app.current_tenant", "val": "tenant-123"}   # value never interpolated
    assert "set_config" in seen["sql"]
