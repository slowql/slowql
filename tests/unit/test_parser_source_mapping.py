# tests/unit/test_parser_source_mapping.py
from slowql.parser.universal import UniversalParser


def test_single_statement_preserves_raw_and_offsets():
    sql = "SELECT * FROM users"
    parser = UniversalParser()
    queries = parser.parse(sql)

    assert len(queries) == 1
    query = queries[0]
    assert query.raw == "SELECT * FROM users"
    assert query.start_offset == 0
    assert query.end_offset == 19
    assert query.location.line == 1
    assert query.location.column == 1

def test_single_statement_with_semicolon():
    sql = "SELECT 1;"
    parser = UniversalParser()
    queries = parser.parse(sql)

    assert len(queries) == 1
    query = queries[0]
    assert query.raw == "SELECT 1;"
    assert query.start_offset == 0
    assert query.end_offset == 9
    assert query.location.line == 1
    assert query.location.column == 1

def test_multiple_statements_splitting():
    sql = "SELECT 1; SELECT 2 ;  SELECT 3"
    parser = UniversalParser()
    queries = parser.parse(sql)

    assert len(queries) == 3

    assert queries[0].raw == "SELECT 1;"
    assert queries[0].start_offset == 0

    assert queries[1].raw == "SELECT 2 ;"
    assert queries[1].start_offset == 10

    assert queries[2].raw == "SELECT 3"
    assert queries[2].start_offset == 22

def test_semicolon_inside_string_does_not_split():
    sql = "SELECT 'a;b'; SELECT 2"
    parser = UniversalParser()
    queries = parser.parse(sql)

    assert len(queries) == 2
    assert queries[0].raw == "SELECT 'a;b';"
    assert queries[1].raw == "SELECT 2"

def test_comments_before_statement_are_excluded_from_raw():
    sql = "-- line comment\n/* block \n comment */ SELECT 1"
    parser = UniversalParser()
    queries = parser.parse(sql)

    assert len(queries) == 1
    query = queries[0]
    assert query.raw == "SELECT 1"
    # SELECT starts after "-- line comment\n" (16 chars) and "/* block \n comment */ " (21 chars)
    # Total prefix: 16 + 21 = 37 chars. 'S' is at offset 37.
    assert query.start_offset == 38
    assert query.location.line == 3
    assert query.location.column == 13

def test_multiple_statements_with_comments():
    sql = """
    -- first
    SELECT 1;
    /* second */
    SELECT 2;
    """
    parser = UniversalParser()
    queries = parser.parse(sql)

    assert len(queries) == 2

    assert queries[0].raw == "SELECT 1;"
    assert queries[0].location.line == 3

    assert queries[1].raw == "SELECT 2;"
    assert queries[1].location.line == 5

def test_semicolon_in_comments():
    sql = "-- comment; \n SELECT 1; /* comment; */ SELECT 2"
    parser = UniversalParser()
    queries = parser.parse(sql)

    assert len(queries) == 2
    assert queries[0].raw == "SELECT 1;"
    assert queries[1].raw == "SELECT 2"

def test_trailing_whitespace_after_semicolon_is_excluded():
    sql = "SELECT 1;   "
    parser = UniversalParser()
    queries = parser.parse(sql)

    assert len(queries) == 1
    assert queries[0].raw == "SELECT 1;"
    assert queries[0].end_offset == 9  # Includes ';' but not '   '
