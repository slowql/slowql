from slowql.parser.extractor import SQLExtractor


def test_extract_python_static_string():
    content = """
query = "SELECT * FROM users"
    """
    extractor = SQLExtractor()
    results = extractor.extract_from_python(content, "test.py")
    assert len(results) == 1
    assert results[0].raw == "SELECT * FROM users"
    assert results[0].line == 2
    assert results[0].is_dynamic is False

def test_extract_python_f_string():
    content = """
query = f"SELECT * FROM users WHERE id = {user_id}"
    """
    extractor = SQLExtractor()
    results = extractor.extract_from_python(content, "test.py")
    assert len(results) == 1
    assert "SELECT * FROM users WHERE id =" in results[0].raw
    assert results[0].is_dynamic is True

def test_extract_python_multiline():
    content = """
query = \"\"\"
    SELECT *
    FROM users
    WHERE id = 1
\"\"\"
    """
    extractor = SQLExtractor()
    results = extractor.extract_from_python(content, "test.py")
    assert len(results) == 1
    assert "SELECT *" in results[0].raw
    assert "FROM users" in results[0].raw

def test_extract_typescript_template_literal():
    content = """
const query = `SELECT * FROM users WHERE id = ${id}`;
    """
    extractor = SQLExtractor()
    results = extractor.extract_from_typescript(content, "test.ts")
    assert len(results) == 1
    assert "SELECT * FROM users" in results[0].raw
    assert results[0].is_dynamic is True

def test_extract_java_string():
    content = """
String query = "SELECT * FROM users";
    """
    extractor = SQLExtractor()
    results = extractor.extract_from_java(content, "Test.java")
    assert len(results) == 1
    assert results[0].raw == "SELECT * FROM users"

def test_extract_go_string():
    content = """
query := "SELECT * FROM users"
    """
    extractor = SQLExtractor()
    results = extractor.extract_from_go(content, "test.go")
    assert len(results) == 1
    assert results[0].raw == "SELECT * FROM users"

def test_extract_ruby_string():
    content = """
query = "SELECT * FROM users"
    """
    extractor = SQLExtractor()
    results = extractor.extract_from_ruby(content, "test.rb")
    assert len(results) == 1
    assert results[0].raw == "SELECT * FROM users"
