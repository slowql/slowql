from slowql.core.engine import SlowQL


def test_jinja_if_block():
    engine = SlowQL(auto_discover=False)
    sql = """
    SELECT * FROM users
    {% if is_active %}
      WHERE status = 'active'
    {% endif %}
    """

    result = engine.analyze(sql)
    assert len(result.queries) == 1
    query = result.queries[0]

    # Check that original Jinja is preserved in raw
    assert "{% if is_active %}" in query.raw
    # Normalized may or may not have space substituted text, but the parse should succeed.
    assert "users" in [t.lower() for t in query.tables]

def test_jinja_ref_expression():
    engine = SlowQL(auto_discover=False)
    sql = "SELECT id, name FROM {{ ref('stg_users') }}"

    result = engine.analyze(sql)
    assert len(result.queries) == 1
    query = result.queries[0]

    assert "{{ ref('stg_users') }}" in query.raw

def test_jinja_for_loop():
    engine = SlowQL(auto_discover=False)
    sql = """
    SELECT
      {% for field in fields %}
        {{ field }},
      {% endfor %}
      id
    FROM table
    """
    result = engine.analyze(sql)
    assert len(result.queries) == 1
    query = result.queries[0]

    assert "{% for field in fields %}" in query.raw

def test_jinja_comments():
    engine = SlowQL(auto_discover=False)
    sql = """
    {# This is a dbt comment #}
    SELECT * FROM table
    """
    result = engine.analyze(sql)
    assert len(result.queries) == 1
    # Comments at start of file are skipped by SourceSplitter, standard behavior
    assert "SELECT * FROM table" in result.queries[0].raw

def test_dbt_missing_ref_rule():
    engine = SlowQL(auto_discover=True)
    # Enable only this rule
    engine.config = engine.config.with_overrides(analysis={"enabled_rules": ["QUAL-DBT-001"]})

    sql = "SELECT * FROM my_table"
    result = engine.analyze(sql)
    assert len(result.issues) == 1
    assert result.issues[0].rule_id == "QUAL-DBT-001"

    sql_ok = "SELECT * FROM {{ ref('my_table') }}"
    result_ok = engine.analyze(sql_ok)
    assert len(result_ok.issues) == 0

def test_dbt_hardcoded_schema_rule():
    engine = SlowQL(auto_discover=True)
    # Enable only this rule
    engine.config = engine.config.with_overrides(analysis={"enabled_rules": ["QUAL-DBT-002"]})

    sql = "SELECT * FROM my_schema.my_table"
    result = engine.analyze(sql)
    assert len(result.issues) == 1
    assert result.issues[0].rule_id == "QUAL-DBT-002"

    sql_ok = "SELECT * FROM {{ source('my_source', 'my_table') }}"
    result_ok = engine.analyze(sql_ok)
    assert len(result_ok.issues) == 0

