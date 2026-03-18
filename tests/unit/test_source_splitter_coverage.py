from slowql.parser.source_splitter import SourceSplitter


def test_source_splitter_basic():
    s = SourceSplitter()
    sql = "SELECT 1; SELECT 2;"
    slices = s.split(sql)
    assert len(slices) == 2
    assert slices[0].raw == "SELECT 1;"
    assert slices[1].raw == "SELECT 2;"

def test_source_splitter_comments():
    s = SourceSplitter()
    sql = """
    -- first query
    SELECT 1;
    /* second
       query */
    SELECT 2;
    """
    slices = s.split(sql)
    assert len(slices) == 2
    assert "SELECT 1;" in slices[0].raw
    assert "SELECT 2;" in slices[1].raw

def test_source_splitter_quotes():
    s = SourceSplitter()
    sql = "SELECT 'semi;colon' as a; SELECT \"another;semi\"; SELECT `back;tick`;"
    slices = s.split(sql)
    assert len(slices) == 3
    assert slices[0].raw == "SELECT 'semi;colon' as a;"
    assert slices[1].raw == "SELECT \"another;semi\";"
    assert slices[2].raw == "SELECT `back;tick`;"

def test_source_splitter_line_col():
    s = SourceSplitter()
    sql = "SELECT 1;\nSELECT 2;"
    slices = s.split(sql)
    assert slices[0].line == 1
    assert slices[0].column == 1
    assert slices[1].line == 2
    assert slices[1].column == 1

def test_source_splitter_empty():
    s = SourceSplitter()
    assert s.split("") == []
    assert s.split("   \n   ") == []

def test_source_splitter_escaped_quotes():
    s = SourceSplitter()
    sql = "SELECT 'it''s escaped;'; SELECT \"nested\"\"quotes;\";"
    slices = s.split(sql)
    assert len(slices) == 2
    assert slices[0].raw == "SELECT 'it''s escaped;';"
    assert slices[1].raw == "SELECT \"nested\"\"quotes;\";"

def test_source_splitter_unclosed_quotes():
    s = SourceSplitter()
    sql = "SELECT 'unclosed quote; still parses"
    slices = s.split(sql)
    assert len(slices) == 1
    assert slices[0].raw == "SELECT 'unclosed quote; still parses"

def test_source_splitter_trailing_whitespace():
    s = SourceSplitter()
    sql = "SELECT 1;    \n   "
    slices = s.split(sql)
    assert len(slices) == 1
    assert slices[0].raw == "SELECT 1;"
