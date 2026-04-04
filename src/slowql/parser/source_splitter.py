# slowql/src/slowql/parser/source_splitter.py
"""
SQL statement splitter that preserves source anchoring information.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class StatementSlice:
    """
    A slice of an original SQL string corresponding to a single statement.

    Attributes:
        raw: The exact raw text of the statement.
        start_offset: The character offset where the statement starts.
        end_offset: The character offset where the statement ends (exclusive).
        line: The 1-indexed line number where the statement starts.
        column: The 1-indexed column number where the statement starts.
    """

    raw: str
    start_offset: int
    end_offset: int
    line: int
    column: int


class SourceSplitter:
    """
    Splits a multi-statement SQL string into individual statements while
    preserving exact source text and offsets.
    """

    def split(self, sql: str) -> list[StatementSlice]:
        """
        Split a SQL string into individual statements.

        Args:
            sql: The SQL string to split.

        Returns:
            A list of StatementSlice objects.
        """
        if not sql:
            return []

        slices: list[StatementSlice] = []
        i = 0
        n = len(sql)

        while i < n:
            # 1. Skip leading whitespace and comments to find the true statement start
            stmt_sql_start = self._find_first_token(sql, i, n)
            if stmt_sql_start >= n:
                break

            # 2. Find the end of the statement
            stmt_end, found_semicolon = self._find_statement_end(sql, stmt_sql_start, n)

            # 3. Handle the statement text
            raw = sql[stmt_sql_start:stmt_end]
            if not found_semicolon:
                raw_trimmed = raw.rstrip()
                stmt_end = stmt_sql_start + len(raw_trimmed)
                raw = raw_trimmed

            if raw:
                line, column = self._get_location(sql, stmt_sql_start)
                slices.append(StatementSlice(
                    raw=raw,
                    start_offset=stmt_sql_start,
                    end_offset=stmt_end,
                    line=line,
                    column=column
                ))

            i = stmt_end
            if found_semicolon and i < n and sql[i-1] == ';':
                 # Already incremented in _find_statement_end
                 pass

            # Ensure we always move forward
            if i <= stmt_sql_start and n > 0:
                i = stmt_sql_start + 1

        return slices

    def _find_statement_end(self, sql: str, start: int, n: int) -> tuple[int, bool]:
        """Find the end offset of the current statement and whether it ended with a semicolon."""
        j = start
        block_depth = 0
        start_block_keywords = {"BEGIN", "CASE"}

        while j < n:
            char = sql[j]
            if char in ("'", '"', '`'):
                j = self._skip_quoted(sql, j, n, char)
            elif char == '-' and j + 1 < n and sql[j + 1] == '-':
                j = self._skip_line_comment(sql, j, n)
            elif char == '/' and j + 1 < n and sql[j + 1] == '*':
                j = self._skip_block_comment(sql, j, n)
            elif char == '$' and j + 1 < n:
                j = self._skip_dollar_quoted(sql, j, n)
            elif char.isalpha():
                word = ""
                k = j
                while k < n and (sql[k].isalnum() or sql[k] == '_'):
                    word += sql[k]
                    k += 1

                upper_word = word.upper()
                if upper_word in start_block_keywords:
                    block_depth += 1
                elif upper_word == "END":
                    block_depth = max(0, block_depth - 1)
                j = k
            elif char == ';' and block_depth == 0:
                return j + 1, True
            else:
                j += 1

        return j, False

    def _find_first_token(self, sql: str, start: int, n: int) -> int:
        """Find the index of the first character that is not whitespace or part of a comment."""
        i = start
        while i < n:
            char = sql[i]
            if char.isspace():
                i += 1
            elif char == '-' and i + 1 < n and sql[i + 1] == '-':
                i = self._skip_line_comment(sql, i, n)
            elif char == '/' and i + 1 < n and sql[i + 1] == '*':
                i = self._skip_block_comment(sql, i, n)
            else:
                return i
        return n

    def _get_location(self, sql: str, offset: int) -> tuple[int, int]:
        prefix = sql[:offset]
        line = prefix.count('\n') + 1
        last_newline = prefix.rfind('\n')
        if last_newline == -1:
            column = offset + 1
        else:
            column = offset - last_newline
        return line, column

    def _skip_quoted(self, sql: str, start: int, n: int, quote: str) -> int:
        i = start + 1
        while i < n:
            if sql[i] == quote:
                if i + 1 < n and sql[i + 1] == quote:
                    i += 2
                    continue
                return i + 1
            i += 1
        return n

    def _skip_line_comment(self, sql: str, start: int, n: int) -> int:
        i = start + 2
        while i < n:
            if sql[i] == '\n':
                return i + 1
            i += 1
        return n

    def _skip_block_comment(self, sql: str, start: int, n: int) -> int:
        i = start + 2
        while i < n:
            if sql[i] == '*' and i + 1 < n and sql[i + 1] == '/':
                return i + 2
            i += 1
        return n

    def _skip_dollar_quoted(self, sql: str, start: int, n: int) -> int:
        end_dollar = sql.find('$', start + 1)
        if end_dollar != -1 and end_dollar - start <= 30:
            tag = sql[start:end_dollar + 1]
            inner_tag = tag[1:-1]
            if all(c.isalnum() or c == '_' for c in inner_tag):
                closing_pos = sql.find(tag, end_dollar + 1)
                if closing_pos != -1:
                    return closing_pos + len(tag)
        return start + 1
