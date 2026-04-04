# slowql/src/slowql/parser/mybatis.py
"""
MyBatis XML mapper file SQL extractor.

Extracts SQL statements from MyBatis XML files commonly used in Java/Spring projects.
Supports: <select>, <insert>, <update>, <delete>, <sql> tags.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator

import xml.etree.ElementTree as ET
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class MyBatisQuery:
    """A SQL statement extracted from a MyBatis XML mapper."""
    raw: str
    line: int
    column: int
    file_path: str
    statement_id: str
    statement_type: str  # select, insert, update, delete, sql
    is_dynamic: bool


class MyBatisExtractor:
    """
    Extracts SQL from MyBatis XML mapper files.

    Handles:
    - <select>, <insert>, <update>, <delete> statements
    - <sql> fragments
    - Dynamic SQL tags: <if>, <where>, <set>, <foreach>, <choose>, <when>, <otherwise>, <trim>
    - Parameter placeholders: #{param} and ${param}
    """

    # Tags that contain SQL statements
    SQL_TAGS = frozenset({"select", "insert", "update", "delete", "sql"})

    # Dynamic SQL control tags (content should still be analyzed)
    DYNAMIC_TAGS = frozenset({
        "if", "where", "set", "foreach", "choose",
        "when", "otherwise", "trim", "bind"
    })

    # Parameter patterns that indicate dynamic SQL
    DYNAMIC_PARAM_RE = re.compile(r"\$\{[^}]+\}")  # ${param} is dynamic/unsafe
    SAFE_PARAM_RE = re.compile(r"#\{[^}]+\}")      # #{param} is parameterized/safe

    def extract(self, content: str, file_path: str) -> list[MyBatisQuery]:
        """
        Extract all SQL statements from MyBatis XML content.

        Args:
            content: The XML file content
            file_path: Path to the source file (for error reporting)

        Returns:
            List of extracted MyBatis queries
        """
        queries = []

        # Build line offset map for accurate line numbers
        line_offsets = self._build_line_offsets(content)

        try:
            # Parse XML
            root = ET.fromstring(content)
        except ET.ParseError:
            # If XML is malformed, try regex fallback
            return self._extract_via_regex(content, file_path)

        # Find all SQL-containing tags
        for tag_name in self.SQL_TAGS:
            for element in root.iter(tag_name):
                query = self._extract_from_element(element, tag_name, file_path, content, line_offsets)
                if query:
                    queries.append(query)

        return queries

    def _extract_from_element(
        self,
        element: ET.Element,
        tag_name: str,
        file_path: str,
        content: str,
        line_offsets: list[int]
    ) -> MyBatisQuery | None:
        """Extract SQL from a single XML element."""

        # Get statement ID (e.g., <select id="findUserById">)
        statement_id = element.get("id", "anonymous")

        # Extract all text content, including from nested dynamic tags
        sql_parts = list(self._collect_sql_text(element))
        if not sql_parts:
            return None

        raw_sql = " ".join(sql_parts)

        # Check if SQL contains dynamic parameters BEFORE normalization
        has_dynamic_params = bool(self.DYNAMIC_PARAM_RE.search(raw_sql))

        raw_sql = self._normalize_sql(raw_sql)

        if not raw_sql.strip():
            return None
        has_dynamic_tags = any(
            element.find(f".//{tag}") is not None
            for tag in self.DYNAMIC_TAGS
        )
        is_dynamic = has_dynamic_params or has_dynamic_tags

        # Find line number by searching for the tag in original content
        line, column = self._find_element_position(element, tag_name, statement_id, content, line_offsets)

        return MyBatisQuery(
            raw=raw_sql,
            line=line,
            column=column,
            file_path=file_path,
            statement_id=statement_id,
            statement_type=tag_name,
            is_dynamic=is_dynamic
        )

    def _collect_sql_text(self, element: ET.Element) -> Iterator[str]:  # noqa: PLR0912
        """Recursively collect all SQL text from an element and its children."""
        # Get direct text
        if element.text:
            yield element.text.strip()

        # Process children with semantic awareness
        for child in element:
            tag = child.tag.lower() if isinstance(child.tag, str) else ""

            if tag == "set":
                # Reconstruct SET keyword + contents
                set_parts = list(self._collect_sql_text(child))
                if set_parts:
                    # Join parts, strip trailing comma
                    set_body = " ".join(p for p in set_parts if p)
                    set_body = set_body.rstrip().rstrip(",")
                    yield f"SET {set_body}"
            elif tag == "where":
                # Reconstruct WHERE keyword + contents
                where_parts = list(self._collect_sql_text(child))
                if where_parts:
                    where_body = " ".join(p for p in where_parts if p)
                    # Strip leading AND/OR
                    where_body = re.sub(r"^\s*(AND|OR)\s+", "", where_body, flags=re.IGNORECASE)
                    yield f"WHERE {where_body}"
            elif tag == "trim":
                # Handle <trim prefix="WHERE"> etc.
                prefix = child.get("prefix", "")
                prefix_overrides = child.get("prefixOverrides", "")
                trim_parts = list(self._collect_sql_text(child))
                if trim_parts:
                    trim_body = " ".join(p for p in trim_parts if p)
                    if prefix_overrides:
                        for po in prefix_overrides.split("|"):
                            trim_body = re.sub(
                                rf"^\s*{po.strip()}\s+", "", trim_body, flags=re.IGNORECASE
                            )
                    if prefix:
                        yield f"{prefix} {trim_body}"
                    else:
                        yield trim_body
            else:
                # Default: recurse into child
                yield from self._collect_sql_text(child)

            # Get tail text (text after closing tag)
            if child.tail:
                yield child.tail.strip()

    def _normalize_sql(self, sql: str) -> str:
        """Normalize SQL whitespace and placeholders."""
        # Collapse multiple whitespace
        sql = re.sub(r"\s+", " ", sql)

        sql = self.SAFE_PARAM_RE.sub("?", sql)

        sql = self.DYNAMIC_PARAM_RE.sub("__DYNAMIC__", sql)

        return sql.strip()

    def _build_line_offsets(self, content: str) -> list[int]:
        """Build a list of character offsets for each line start."""
        offsets = [0]
        for i, char in enumerate(content):
            if char == "\n":
                offsets.append(i + 1)
        return offsets

    def _find_element_position(
        self,
        element: ET.Element,
        tag_name: str,
        statement_id: str,
        content: str,
        line_offsets: list[int],
    ) -> tuple[int, int]:
        """Find the line and column of an element in the original content."""
        lines = content.splitlines()
        for line_num, line_text in enumerate(lines, 1):
            line_lower = line_text.lower()
            if f"<{tag_name}" not in line_lower:
                continue
            if statement_id != "anonymous":
                normalized = line_lower.replace(" ", "")
                if (
                    f'id="{statement_id.lower()}"' in normalized
                    or f"id='{statement_id.lower()}'" in normalized
                ):
                    col = line_text.lower().find(f"<{tag_name}") + 1
                    return line_num, max(col, 1)
            else:
                col = line_text.lower().find(f"<{tag_name}") + 1
                return line_num, max(col, 1)
        return 1, 1  # Fallback
        return 1, 1  # Default if not found

    def _extract_via_regex(self, content: str, file_path: str) -> list[MyBatisQuery]:
        """
        Fallback regex extraction for malformed XML.
        Less accurate but still useful.
        """
        queries = []

        for tag_name in self.SQL_TAGS:
            # Match <select id="...">...</select>
            pattern = rf"<{tag_name}([^>]*)>(.*?)</{tag_name}>"

            for match in re.finditer(pattern, content, re.IGNORECASE | re.DOTALL):
                attrs = match.group(1)
                sql_content = match.group(2)

                # Extract ID from attributes
                id_match = re.search(r'id\s*=\s*["\'](\w+)["\']', attrs)
                statement_id = id_match.group(1) if id_match else "anonymous"

                # Strip XML tags from content
                sql = re.sub(r"<[^>]+>", " ", sql_content)
                sql = self._normalize_sql(sql)

                if not sql.strip():
                    continue

                # Calculate line number
                prefix = content[:match.start()]
                line = prefix.count("\n") + 1

                has_dynamic = bool(self.DYNAMIC_PARAM_RE.search(sql_content))

                queries.append(MyBatisQuery(
                    raw=sql,
                    line=line,
                    column=1,
                    file_path=file_path,
                    statement_id=statement_id,
                    statement_type=tag_name,
                    is_dynamic=has_dynamic
                ))

        return queries


def is_mybatis_file(path: str) -> bool:
    """Check if a file is likely a MyBatis mapper XML."""
    path_lower = path.lower()
    if not path_lower.endswith(".xml"):
        return False
    # Common patterns: *Mapper.xml, *DAO.xml, or in mapper/mybatis directories
    return any([
        "mapper" in path_lower,
        "mybatis" in path_lower,
        path_lower.endswith("dao.xml"),
    ])
