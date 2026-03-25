from slowql.core.engine import SlowQL
from slowql.core.models import Severity


def test_analyze_python_file_with_injection(tmp_path):
    py_file = tmp_path / "app.py"
    py_file.write_text("""
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)

def list_products():
    query = "SELECT * FROM products"
    return db.execute(query)
""")

    engine = SlowQL()
    result = engine.analyze_files([py_file])

    # Should find 2 queries
    assert len(result.queries) == 2

    # Should find at least one security issue for the f-string
    security_issues = [i for i in result.issues if i.rule_id == "SEC-INJ-001"]
    assert len(security_issues) >= 1

    # Check location mapping
    f_string_issue = next(i for i in security_issues if "f-string" in i.message or "dynamic" in i.message)
    assert f_string_issue.location.line == 3
    assert f_string_issue.severity == Severity.CRITICAL

def test_analyze_ts_file_with_injection(tmp_path):
    ts_file = tmp_path / "app.ts"
    ts_file.write_text("const sql = `SELECT * FROM orders WHERE id = ${id}`;")

    engine = SlowQL()
    result = engine.analyze_files([ts_file])

    assert len(result.queries) == 1
    assert any(i.rule_id == "SEC-INJ-001" for i in result.issues)
    assert result.issues[0].location.line == 1
