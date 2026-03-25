# slowql/src/slowql/parser/extractor.py
from __future__ import annotations

import ast
import re
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ExtractedQuery:
    """
    A SQL query extracted from application code.
    """
    raw: str
    line: int
    column: int
    file_path: str
    is_dynamic: bool
    language: str

class SQLExtractor:
    """
    Extracts SQL strings from application code in various languages.
    """

    # Generic SQL pattern: starts with common SQL keywords, ignoring leading whitespace
    SQL_RE = re.compile(
        r"^\s*(SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|WITH|TRUNCATE|GRANT|REVOKE)\b",
        re.IGNORECASE | re.MULTILINE
    )

    def extract_from_python(self, content: str, file_path: str) -> list[ExtractedQuery]:
        """Extract SQL from Python code using AST."""
        queries = []
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return []

        skip_nodes = set()
        for node in ast.walk(tree):
            if node in skip_nodes:
                continue

            # Check for static strings
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if self.SQL_RE.search(node.value):
                    queries.append(ExtractedQuery(
                        raw=node.value.strip(),
                        line=node.lineno,
                        column=node.col_offset + 1,
                        file_path=file_path,
                        is_dynamic=False,
                        language="python"
                    ))
            # Check for f-strings
            elif isinstance(node, ast.JoinedStr):
                # Mark children to be skipped
                for val in node.values:
                    skip_nodes.add(val)

                # Reconstruct a representation of the f-string to check if it's SQL
                parts = []
                for part in node.values:
                    if isinstance(part, ast.Constant):
                        parts.append(str(part.value))
                    elif isinstance(part, ast.FormattedValue):
                        parts.append("__dynamic__")

                full_val = "".join(parts)
                if self.SQL_RE.search(full_val):
                    queries.append(ExtractedQuery(
                        raw=full_val.strip(),
                        line=node.lineno,
                        column=node.col_offset + 1,
                        file_path=file_path,
                        is_dynamic=True,
                        language="python"
                    ))
        return queries

    def extract_from_typescript(self, content: str, file_path: str) -> list[ExtractedQuery]:
        """Extract SQL from TypeScript/JS code using regex."""
        return self._extract_via_regex(content, file_path, "typescript")

    def extract_from_java(self, content: str, file_path: str) -> list[ExtractedQuery]:
        """Extract SQL from Java code using regex."""
        return self._extract_via_regex(content, file_path, "java")

    def extract_from_go(self, content: str, file_path: str) -> list[ExtractedQuery]:
        """Extract SQL from Go code using regex."""
        return self._extract_via_regex(content, file_path, "go")

    def extract_from_ruby(self, content: str, file_path: str) -> list[ExtractedQuery]:
        """Extract SQL from Ruby code using regex."""
        return self._extract_via_regex(content, file_path, "ruby")

    def _extract_via_regex(self, content: str, file_path: str, language: str) -> list[ExtractedQuery]:
        """
        Generic regex-based extraction for languages where we don't have a full parser.
        Looks for strings (double quotes, single quotes, or backticks) that contain SQL.
        """
        queries = []
        # Matches strings: "...", '...', `...`
        # Handles escaped quotes
        string_pattern = r'("(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|`(?:\\.|[^`\\])*`)'

        for match in re.finditer(string_pattern, content):
            raw_match = match.group(1)
            # Remove the surrounding quotes
            inner_content = raw_match[1:-1]

            if self.SQL_RE.search(inner_content):
                # Calculate line and column
                prefix = content[:match.start()]
                line = prefix.count('\n') + 1
                last_newline = prefix.rfind('\n')
                column = match.start() - last_newline if last_newline != -1 else match.start() + 1

                # Check for dynamic markers depending on language
                is_dynamic = False
                if language in ("typescript", "ruby"):
                    if "${" in inner_content or "#{" in inner_content:
                        is_dynamic = True
                elif language == "go":
                    if "%v" in inner_content or "%s" in inner_content or "%d" in inner_content:
                        is_dynamic = True

                queries.append(ExtractedQuery(
                    raw=inner_content.strip(),
                    line=line,
                    column=column,
                    file_path=file_path,
                    is_dynamic=is_dynamic,
                    language=language
                ))

        return queries
