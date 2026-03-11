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

    def split(self, sql: str) -> list[StatementSlice]:  # noqa: PLR0912
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

            # 2. Track where we are in the state machine to find the semicolon
            j = stmt_sql_start
            found_semicolon = False
            while j < n:
                char = sql[j]
                if char == "'":
                    j = self._skip_quoted(sql, j, n, "'")
                elif char == '"':
                    j = self._skip_quoted(sql, j, n, '"')
                elif char == '`':
                    j = self._skip_quoted(sql, j, n, '`')
                elif char == '-' and j + 1 < n and sql[j + 1] == '-':
                    j = self._skip_line_comment(sql, j, n)
                elif char == '/' and j + 1 < n and sql[j + 1] == '*':
                    j = self._skip_block_comment(sql, j, n)
                elif char == ';':
                    found_semicolon = True
                    j += 1
                    break
                else:
                    j += 1

            # 3. We found a statement boundary (semicolon or EOF)
            # The raw text is from stmt_sql_start to j, but we trim trailing whitespace (except the ;)
            stmt_end = j
            raw = sql[stmt_sql_start:stmt_end]

            # If we didn't end on a semicolon, we might have trailing whitespace to trim
            if not found_semicolon:
                raw_trimmed = raw.rstrip()
                stmt_end = stmt_sql_start + len(raw_trimmed)
                raw = raw_trimmed
            else:
                # If we have a semicolon, it's at j-1. We should trim whitespace BETWEEN the last token and ; if needed?
                # Actually, "exclude trailing whitespace after the statement terminator"
                # If sql is "SELECT 1;  ", raw should be "SELECT 1;"
                # Current j is after the semicolon. So raw is "SELECT 1;" (if it was "SELECT 1; ")
                # Let's just rstrip the raw but ensure if last char was ;, we keep it.
                # Simplified: raw is already mapped to j. If we found a semicolon, j is just after it.
                # If there was a semicolon, we don't trim anything because the semicolon is the terminator.
                # Wait, "SELECT 1 ;  " -> raw should be "SELECT 1 ;"
                # My logic: stmt_sql_start="S", j=" " (after ;). raw="SELECT 1 ;". Correct.
                pass

            if raw:
                # Calculate line/column for stmt_sql_start
                line, column = self._get_location(sql, stmt_sql_start)
                slices.append(StatementSlice(
                    raw=raw,
                    start_offset=stmt_sql_start,
                    end_offset=stmt_end,
                    line=line,
                    column=column
                ))

            # Move i to j to continue searching for the next statement
            i = j

        return slices

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
