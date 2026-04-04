"""Integration tests for MyBatis XML mapper file support."""
import tempfile
from pathlib import Path

from slowql import SlowQL


def test_mybatis_basic_extraction():
    """Test basic SQL extraction from MyBatis XML."""
    mybatis_xml = """<?xml version="1.0" encoding="UTF-8"?>
<mapper namespace="com.example.UserMapper">
    <select id="findUserById" resultType="User">
        SELECT * FROM users WHERE id = #{id}
    </select>
    <insert id="insertUser">
        INSERT INTO users (name, email) VALUES (#{name}, #{email})
    </insert>
</mapper>
"""

    with tempfile.NamedTemporaryFile(mode='w', suffix='Mapper.xml', delete=False) as f:
        f.write(mybatis_xml)
        f.flush()

        engine = SlowQL()
        result = engine.analyze_file(f.name)

        assert len(result.queries) == 2
        assert any('SELECT' in q.raw for q in result.queries)
        assert any('INSERT' in q.raw for q in result.queries)

        # Should detect SELECT *
        select_star_issues = [i for i in result.issues if 'PERF-SCAN-001' in i.rule_id]
        assert len(select_star_issues) >= 1

        Path(f.name).unlink()


def test_mybatis_dynamic_sql_detection():
    """Test detection of unsafe ${} interpolation."""
    mybatis_xml = """<?xml version="1.0" encoding="UTF-8"?>
<mapper namespace="com.example.UserMapper">
    <select id="findUsers">
        SELECT * FROM users WHERE name = ${unsafeName}
    </select>
</mapper>
"""

    with tempfile.NamedTemporaryFile(mode='w', suffix='Mapper.xml', delete=False) as f:
        f.write(mybatis_xml)
        f.flush()

        engine = SlowQL()
        result = engine.analyze_file(f.name)

        assert len(result.queries) == 1
        # The query should be marked as dynamic due to ${}
        assert result.queries[0].is_dynamic

        Path(f.name).unlink()


def test_mybatis_nested_dynamic_tags():
    """Test SQL extraction with <if>, <where>, <set> tags."""
    mybatis_xml = """<?xml version="1.0" encoding="UTF-8"?>
<mapper namespace="com.example.UserMapper">
    <update id="updateUser">
        UPDATE users
        <set>
            <if test="name != null">name = #{name},</if>
            <if test="email != null">email = #{email},</if>
        </set>
        WHERE id = #{id}
    </update>
</mapper>
"""

    with tempfile.NamedTemporaryFile(mode='w', suffix='Mapper.xml', delete=False) as f:
        f.write(mybatis_xml)
        f.flush()

        engine = SlowQL()
        result = engine.analyze_file(f.name)

        assert len(result.queries) == 1
        assert 'UPDATE' in result.queries[0].raw
        # Should be marked as dynamic due to <if> tags
        assert result.queries[0].is_dynamic

        Path(f.name).unlink()


def test_mybatis_file_detection():
    """Test that only valid MyBatis files are recognized."""
    from slowql.parser.mybatis import is_mybatis_file

    assert is_mybatis_file("UserMapper.xml")
    assert is_mybatis_file("src/main/resources/mapper/UserMapper.xml")
    assert is_mybatis_file("mybatis/UserDAO.xml")

    assert not is_mybatis_file("config.xml")
    assert not is_mybatis_file("pom.xml")
    assert not is_mybatis_file("test.sql")


def test_mybatis_recursive_directory_scan():
    """Test that engine recursively scans directories for MyBatis XML files."""
    import tempfile

    from slowql.core.config import AnalysisConfig, Config

    with tempfile.TemporaryDirectory() as tmpdir:
        # Multi-service structure
        for svc, mapper, sql in [
            ("service-a", "UserMapper", "SELECT * FROM users WHERE id = #{id}"),
            ("service-b", "OrderMapper", "SELECT * FROM orders WHERE user_id = #{userId}"),
        ]:
            path = Path(tmpdir) / svc / "src" / "main" / "resources" / "mapper"
            path.mkdir(parents=True)
            (path / f"{mapper}.xml").write_text(f"""<?xml version="1.0" encoding="UTF-8"?>
<mapper namespace="com.example.{mapper}">
    <select id="findById" resultType="Result">
        {sql}
    </select>
</mapper>""")

        config = Config(analysis=AnalysisConfig(parallel=False))
        engine = SlowQL(config=config)
        result = engine.analyze_files([Path(tmpdir)])

        assert len(result.queries) >= 2
        sqls = [q.raw for q in result.queries]
        assert any("users" in s for s in sqls)
        assert any("orders" in s for s in sqls)


def test_mybatis_non_mapper_xml_ignored():
    """Test that non-MyBatis XML files are not parsed as SQL."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmpdir:
        p = Path(tmpdir)
        (p / "pom.xml").write_text("<project><groupId>com.example</groupId></project>")
        (p / "config.xml").write_text("<config><setting key='x' value='y'/></config>")
        mapper_path = p / "mapper"
        mapper_path.mkdir()
        (mapper_path / "UserMapper.xml").write_text("""<?xml version="1.0" encoding="UTF-8"?>
<mapper namespace="com.example.UserMapper">
    <select id="findAll" resultType="User">SELECT id FROM users</select>
</mapper>""")

        from slowql.core.config import AnalysisConfig, Config
        config = Config(analysis=AnalysisConfig(parallel=False))
        engine = SlowQL(config=config)
        result = engine.analyze_files([p])

        non_sql = [q for q in result.queries if "<" in q.raw or "project" in q.raw]
        assert len(non_sql) == 0
        assert len(result.queries) >= 1


def test_mybatis_malformed_xml_fallback():
    """Test regex fallback for malformed XML."""
    from slowql.parser.mybatis import MyBatisExtractor

    malformed = """<?xml version="1.0"?>
<mapper namespace="test">
    <select id="findUser">
        SELECT * FROM users WHERE id = #{id}
    </select>
    <insert id="insertUser">
        INSERT INTO users (name) VALUES (#{name})
    </insert>
    <!-- unclosed tag below to break parser -->
    <update id="bad"
</mapper>"""

    extractor = MyBatisExtractor()
    queries = extractor.extract(malformed, "bad.xml")
    # Should not crash, may return partial results via regex fallback
    assert isinstance(queries, list)


def test_mybatis_where_tag_reconstruction():
    """Test <where> tag produces correct WHERE clause."""
    from slowql.parser.mybatis import MyBatisExtractor

    xml = """<?xml version="1.0"?>
<mapper namespace="test">
    <select id="search" resultType="User">
        SELECT id, name FROM users
        <where>
            <if test="name != null">AND name = #{name}</if>
            <if test="status != null">AND status = #{status}</if>
        </where>
    </select>
</mapper>"""

    extractor = MyBatisExtractor()
    queries = extractor.extract(xml, "test.xml")

    assert len(queries) == 1
    sql = queries[0].raw.upper()
    assert "WHERE" in sql
    # WHERE keyword must appear after FROM clause, not as part of SELECT columns
    where_pos = sql.index("WHERE")
    from_pos = sql.index("FROM")
    assert where_pos > from_pos
    assert not sql.upper().startswith("SELECT ID, NAME FROM USERS AND")


def test_mybatis_set_tag_reconstruction():
    """Test <set> tag produces correct SET clause without trailing comma."""
    from slowql.parser.mybatis import MyBatisExtractor

    xml = """<?xml version="1.0"?>
<mapper namespace="test">
    <update id="updateUser">
        UPDATE users
        <set>
            <if test="name != null">name = #{name},</if>
            <if test="email != null">email = #{email},</if>
        </set>
        WHERE id = #{id}
    </update>
</mapper>"""

    extractor = MyBatisExtractor()
    queries = extractor.extract(xml, "test.xml")

    assert len(queries) == 1
    sql = queries[0].raw
    assert "SET" in sql.upper()
    assert "WHERE" in sql.upper()
    assert ",," not in sql
    assert ", WHERE" not in sql


def test_mybatis_location_accuracy():
    """Test that extracted queries report accurate line numbers."""
    from slowql.parser.mybatis import MyBatisExtractor

    xml = """<?xml version="1.0" encoding="UTF-8"?>
<mapper namespace="com.example.UserMapper">
    <select id="findUserById" resultType="User">
        SELECT * FROM users WHERE id = #{id}
    </select>
    <insert id="insertUser">
        INSERT INTO users (name) VALUES (#{name})
    </insert>
</mapper>"""

    extractor = MyBatisExtractor()
    queries = extractor.extract(xml, "UserMapper.xml")

    select_q = next(q for q in queries if q.statement_id == "findUserById")
    insert_q = next(q for q in queries if q.statement_id == "insertUser")

    # select tag is at line 3, insert at line 6
    assert select_q.line == 3
    assert insert_q.line == 6
    # Neither should be 1:1 fallback when they clearly have distinct positions
    assert select_q.line != insert_q.line
