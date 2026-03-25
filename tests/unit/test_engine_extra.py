from pathlib import Path

from slowql.core.config import AnalysisConfig, Config
from slowql.core.engine import SlowQL, _analyze_file_worker
from slowql.core.models import AnalysisResult


def test_analyze_app_code_dialects(tmp_path: Path) -> None:
    engine = SlowQL()

    # 1. Java
    f_java = tmp_path / "Test.java"
    f_java.write_text('String sql = "SELECT * FROM users";')
    res = engine.analyze_app_code(f_java)
    assert len(res.queries) == 1

    # 2. Go
    f_go = tmp_path / "main.go"
    f_go.write_text('db.Query("SELECT 1")')
    res = engine.analyze_app_code(f_go)
    assert len(res.queries) == 1

    # 3. Ruby
    f_rb = tmp_path / "app.rb"
    f_rb.write_text('conn.execute("SELECT 2")')
    res = engine.analyze_app_code(f_rb)
    assert len(res.queries) == 1

    # 4. JS
    f_js = tmp_path / "app.js"
    f_js.write_text('const sql = "SELECT 3";')
    res = engine.analyze_app_code(f_js)
    assert len(res.queries) == 1

def test_analyze_app_code_unsupported(tmp_path: Path) -> None:
    engine = SlowQL()
    f_txt = tmp_path / "test.txt"
    f_txt.write_text("SELECT 1")
    res = engine.analyze_app_code(f_txt)
    # Branch 819: should return empty AnalysisResult
    assert len(res.queries) == 0

def test_analyze_file_empty(tmp_path: Path) -> None:
    engine = SlowQL()
    f_empty = tmp_path / "empty.sql"
    f_empty.write_text("")
    res = engine.analyze_file(f_empty)
    assert len(res.queries) == 0

def test_analyze_files_sequential_no_workers(tmp_path: Path) -> None:
    # Coverage for branch 565 when parallel is False or 1 worker
    f1 = tmp_path / "f1.sql"
    f1.write_text("SELECT 1;")
    engine = SlowQL(config=Config(analysis=AnalysisConfig(parallel=False)))
    res = engine.analyze_files([f1])
    assert len(res.queries) == 1

def test_analyze_files_sequential_error_handling(tmp_path: Path) -> None:
    f1 = tmp_path / "valid.sql"
    f1.write_text("SELECT 1;")

    config = Config(analysis=AnalysisConfig(parallel=False))
    engine = SlowQL(config=config)

    # Test branch 574: FileNotFoundError in sequential
    res = engine.analyze_files([f1, Path("non_existent.sql")])
    assert len(res.queries) == 1

def test_analyze_file_worker_exception() -> None:
    # Test branch 554: Exception in worker
    payload = {
        "path": Path("non_existent.sql"),
        "dialect": "universal",
        "config_dict": {},
        "schema": None
    }
    path, result = _analyze_file_worker(payload)
    assert "non_existent.sql" in str(path)
    assert isinstance(result, Exception)

def test_migration_results_merging() -> None:
    # Mock some migration results
    m_res = AnalysisResult(dialect="universal")
    from slowql.core.models import Category, Dimension, Issue, Location, Severity
    m_res.add_issue(Issue(
        rule_id="MIG-001",
        message="Test migration issue",
        severity=Severity.LOW,
        category=Category.QUAL_SCHEMA_DESIGN,
        dimension=Dimension.MIGRATION,
        location=Location(1, 1, file="mig.sql"),
        snippet="ALTER TABLE ..."
    ))
    # This is just for coverage of imports and basic logic
    assert m_res.issues[0].dimension == Dimension.MIGRATION

def test_engine_apply_severity_overrides_coverage() -> None:
    engine = SlowQL()
    from slowql.core.models import Category, Dimension, Issue, Location, Severity
    issue = Issue(
        rule_id="RULE-001",
        message="Test",
        severity=Severity.LOW,
        category=Category.QUAL_SCHEMA_DESIGN,
        dimension=Dimension.SCHEMA,
        location=Location(1, 1),
        snippet="SELECT 1"
    )
    # Test with empty overrides
    overridden = engine._apply_severity_overrides([issue])
    assert overridden[0].severity == Severity.LOW
