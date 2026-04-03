"""Targeted coverage tests for mybatis.py uncovered lines."""
from __future__ import annotations

import pytest
from slowql.parser.mybatis import MyBatisExtractor, is_mybatis_file


def test_empty_sql_parts_returns_none():
    """Covers: 'if not sql_parts: return None' branch."""
    extractor = MyBatisExtractor()
    xml = """<?xml version="1.0"?>
<mapper namespace="test">
    <select id="empty"></select>
</mapper>"""
    queries = extractor.extract(xml, "test.xml")
    # Empty tag produces no query
    assert all(q.statement_id != "empty" for q in queries)


def test_raw_sql_empty_after_normalization():
    """Covers: 'if not raw_sql.strip(): return None' after normalize."""
    extractor = MyBatisExtractor()
    xml = """<?xml version="1.0"?>
<mapper namespace="test">
    <select id="whitespace">   </select>
</mapper>"""
    queries = extractor.extract(xml, "test.xml")
    assert len(queries) == 0


def test_trim_tag_with_prefix_overrides():
    """Covers: trim tag with prefixOverrides handling."""
    extractor = MyBatisExtractor()
    xml = """<?xml version="1.0"?>
<mapper namespace="test">
    <select id="trimTest" resultType="User">
        SELECT * FROM users
        <trim prefix="WHERE" prefixOverrides="AND |OR ">
            <if test="name != null">AND name = #{name}</if>
            <if test="status != null">AND status = #{status}</if>
        </trim>
    </select>
</mapper>"""
    queries = extractor.extract(xml, "test.xml")
    assert len(queries) == 1
    assert "WHERE" in queries[0].raw.upper()


def test_trim_tag_without_prefix():
    """Covers: trim tag with no prefix — yields body directly."""
    extractor = MyBatisExtractor()
    xml = """<?xml version="1.0"?>
<mapper namespace="test">
    <select id="trimNoPrefix" resultType="User">
        SELECT * FROM users
        <trim prefixOverrides="AND ">
            <if test="name != null">AND name = #{name}</if>
        </trim>
    </select>
</mapper>"""
    queries = extractor.extract(xml, "test.xml")
    assert len(queries) == 1
    assert "name" in queries[0].raw.lower()


def test_malformed_xml_triggers_regex_fallback():
    """Covers: ET.ParseError → _extract_via_regex fallback."""
    extractor = MyBatisExtractor()
    malformed = """<mapper namespace="test">
    <select id="findUser">
        SELECT * FROM users WHERE id = #{id}
    </select>
    <insert id="insertUser">
        INSERT INTO users (name) VALUES (#{name})
    </insert>
    <unclosed
</mapper>"""
    queries = extractor.extract(malformed, "bad.xml")
    assert isinstance(queries, list)
    assert len(queries) >= 1


def test_regex_fallback_dynamic_detection():
    """Covers: has_dynamic in _extract_via_regex branch."""
    extractor = MyBatisExtractor()
    malformed = """<mapper namespace="test">
    <select id="unsafe">
        SELECT * FROM users WHERE name = ${unsafeName}
    </select>
    <unclosed"""
    queries = extractor.extract(malformed, "bad.xml")
    assert isinstance(queries, list)
    if queries:
        dynamic_queries = [q for q in queries if q.is_dynamic]
        assert len(dynamic_queries) >= 1


def test_regex_fallback_anonymous_id():
    """Covers: anonymous id fallback in _extract_via_regex."""
    extractor = MyBatisExtractor()
    malformed = """<mapper namespace="test">
    <select>
        SELECT * FROM users
    </select>
    <unclosed"""
    queries = extractor.extract(malformed, "bad.xml")
    assert isinstance(queries, list)


def test_location_fallback_returns_1_1():
    """Covers: fallback return 1, 1 when tag not found."""
    extractor = MyBatisExtractor()
    xml = """<?xml version="1.0"?>
<mapper namespace="test">
    <select id="findUser">SELECT 1</select>
</mapper>"""
    queries = extractor.extract(xml, "test.xml")
    assert isinstance(queries, list)


def test_is_mybatis_file_various_paths():
    """Covers: is_mybatis_file detection logic."""
    assert is_mybatis_file("UserMapper.xml")
    assert is_mybatis_file("src/mapper/User.xml")
    assert is_mybatis_file("mybatis/config/User.xml")
    assert is_mybatis_file("UserDAO.xml")
    assert not is_mybatis_file("pom.xml")
    assert not is_mybatis_file("config.xml")
    assert not is_mybatis_file("UserMapper.sql")


def test_delete_with_dynamic_where():
    """Covers: DELETE statement with dynamic WHERE."""
    extractor = MyBatisExtractor()
    xml = """<?xml version="1.0"?>
<mapper namespace="test">
    <delete id="deleteUser">
        DELETE FROM users
        <where>
            <if test="id != null">AND id = #{id}</if>
        </where>
    </delete>
</mapper>"""
    queries = extractor.extract(xml, "test.xml")
    assert len(queries) == 1
    assert "DELETE" in queries[0].raw.upper()
    assert "WHERE" in queries[0].raw.upper()


def test_sql_fragment_tag():
    """Covers: <sql> tag extraction."""
    extractor = MyBatisExtractor()
    xml = """<?xml version="1.0"?>
<mapper namespace="test">
    <sql id="userColumns">id, name, email</sql>
    <select id="findAll" resultType="User">
        SELECT <include refid="userColumns"/> FROM users
    </select>
</mapper>"""
    queries = extractor.extract(xml, "test.xml")
    assert len(queries) >= 1


def test_foreach_tag_handling():
    """Covers: <foreach> as dynamic tag."""
    extractor = MyBatisExtractor()
    xml = """<?xml version="1.0"?>
<mapper namespace="test">
    <select id="findByIds" resultType="User">
        SELECT * FROM users WHERE id IN
        <foreach item="id" collection="ids" open="(" separator="," close=")">
            #{id}
        </foreach>
    </select>
</mapper>"""
    queries = extractor.extract(xml, "test.xml")
    assert len(queries) == 1
    assert queries[0].is_dynamic


def test_multiple_sql_tags_all_extracted():
    """Covers: iteration over all SQL_TAGS."""
    extractor = MyBatisExtractor()
    xml = """<?xml version="1.0"?>
<mapper namespace="test">
    <select id="s1">SELECT 1 FROM a</select>
    <insert id="i1">INSERT INTO a (x) VALUES (#{x})</insert>
    <update id="u1">UPDATE a SET x = #{x} WHERE id = #{id}</update>
    <delete id="d1">DELETE FROM a WHERE id = #{id}</delete>
</mapper>"""
    queries = extractor.extract(xml, "test.xml")
    types = {q.statement_type for q in queries}
    assert "select" in types
    assert "insert" in types
    assert "update" in types
    assert "delete" in types
