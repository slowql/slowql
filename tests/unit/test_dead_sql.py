
from slowql.core.engine import SlowQL


def test_unreachable_code_after_return():
    sql = """
    CREATE PROCEDURE TestProc()
    AS
    BEGIN
        SELECT 1;
        RETURN;
        SELECT 2;
    END;
    """
    engine = SlowQL()
    result = engine.analyze(sql, dialect="tsql")

    # Verify that we found the unreachable code issue
    unreachable_issues = [i for i in result.issues if i.rule_id == "QUAL-DEAD-002"]
    assert len(unreachable_issues) == 1
    assert "Unreachable code" in unreachable_issues[0].message
    assert "SELECT 2" in unreachable_issues[0].snippet

def test_unused_object_detection():
    sql = """
    CREATE VIEW UnusedView AS SELECT 1;
    CREATE PROCEDURE UnusedProc AS BEGIN SELECT 2; END;
    CREATE FUNCTION UnusedFunc() RETURNS INT AS BEGIN RETURN 1; END;

    CREATE VIEW UsedView AS SELECT 3;
    SELECT * FROM UsedView;
    """
    engine = SlowQL()
    result = engine.analyze(sql, dialect="tsql")

    unused_issues = [i for i in result.issues if i.rule_id == "QUAL-DEAD-001"]
    # We expect 3 unused objects: UnusedView, UnusedProc, UnusedFunc
    assert len(unused_issues) == 3

    messages = [i.message for i in unused_issues]
    assert any("UNUSEDVIEW" in m.upper() for m in messages)
    assert any("UNUSEDPROC" in m.upper() for m in messages)
    assert any("UNUSEDFUNC" in m.upper() for m in messages)
    assert not any("'USEDVIEW'" in m.upper() for m in messages)

def test_duplicate_query_detection():
    sql = """
    SELECT * FROM Users WHERE id = 1;
    SELECT * FROM Users WHERE id = 1; -- Exact duplicate
    SELECT * FROM Users WHERE id = 2;
    SELECT * FROM users WHERE ID = 1; -- Near duplicate (different case/whitespace)
    """
    engine = SlowQL()
    result = engine.analyze(sql)

    dup_issues = [i for i in result.issues if i.rule_id == "QUAL-DEAD-003"]
    # We expect 2 duplicate issues (for the 2nd and 4th queries)
    assert len(dup_issues) == 2
    for issue in dup_issues:
        assert "Duplicate query detected" in issue.message

def test_unused_view_detection():
    sql1 = "CREATE VIEW UnusedView AS SELECT 1;"
    sql2 = "SELECT 1;" # No reference to UnusedView

    engine = SlowQL()
    result = engine.analyze(sql1 + "\n" + sql2)

    unused_issues = [i for i in result.issues if i.rule_id == "QUAL-DEAD-001"]
    assert len(unused_issues) == 1
    assert "UNUSEDVIEW" in unused_issues[0].message.upper()

def test_used_view_detection():
    sql1 = "CREATE VIEW UsedView AS SELECT 1;"
    sql2 = "SELECT * FROM UsedView;"

    engine = SlowQL()
    result = engine.analyze(sql1 + "\n" + sql2)

    unused_issues = [i for i in result.items if i.rule_id == "QUAL-DEAD-001"] if hasattr(result, "items") else [i for i in result.issues if i.rule_id == "QUAL-DEAD-001"]
    assert len(unused_issues) == 0

def test_unused_procedure_detection():
    sql1 = "CREATE PROCEDURE UnusedProc AS BEGIN SELECT 1; END;"
    sql2 = "SELECT 1;"

    engine = SlowQL()
    result = engine.analyze(sql1 + "\n" + sql2, dialect="tsql")

    unused_issues = [i for i in result.issues if i.rule_id == "QUAL-DEAD-001"]
    assert len(unused_issues) == 1
    assert "UNUSEDPROC" in unused_issues[0].message.upper()

def test_near_duplicate_query_detection():
    sql1 = "SELECT * FROM Users WHERE id = 1;"
    sql2 = "SELECT * FROM Users WHERE id = 2;" # Near duplicate (same normalized)
    sql3 = "SELECT name FROM Users;"

    engine = SlowQL()
    result = engine.analyze(sql1 + "\n" + sql2 + "\n" + sql3)

    dup_issues = [i for i in result.issues if i.rule_id == "QUAL-DEAD-003"]
    assert len(dup_issues) >= 1
    assert "duplicate" in dup_issues[0].message.lower()

def test_no_duplicate_queries():
    sql1 = "SELECT * FROM Users;"
    sql2 = "SELECT count(*) FROM Orders;"

    engine = SlowQL()
    result = engine.analyze(sql1 + "\n" + sql2)

    dup_issues = [i for i in result.issues if i.rule_id == "QUAL-DEAD-003"]
    assert len(dup_issues) == 0
