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
