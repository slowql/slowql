# slowql/src/slowql/parser/tokenizer.py
"""
SQL tokenization utilities.

This module provides low-level SQL tokenization for cases where
full parsing is not needed or when analyzing SQL fragments.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum, auto
from typing import Iterator


class TokenType(Enum):
    """Types of SQL tokens."""

    # Keywords
    KEYWORD = auto()

    # Identifiers
    IDENTIFIER = auto()
    QUOTED_IDENTIFIER = auto()

    # Literals
    STRING = auto()
    NUMBER = auto()
    BOOLEAN = auto()
    NULL = auto()

    # Operators
    OPERATOR = auto()
    COMPARISON = auto()
    ARITHMETIC = auto()
    LOGICAL = auto()

    # Punctuation
    LPAREN = auto()
    RPAREN = auto()
    COMMA = auto()
    SEMICOLON = auto()
    DOT = auto()
    COLON = auto()
    DOUBLE_COLON = auto()
    STAR = auto()

    # Special
    COMMENT = auto()
    BLOCK_COMMENT = auto()
    WHITESPACE = auto()
    NEWLINE = auto()
    PLACEHOLDER = auto()

    # Unknown
    UNKNOWN = auto()
    EOF = auto()


# SQL keywords (ANSI SQL + common extensions)
SQL_KEYWORDS: frozenset[str] = frozenset({
    # Data Query
    "SELECT", "FROM", "WHERE", "JOIN", "INNER", "LEFT", "RIGHT", "FULL",
    "OUTER", "CROSS", "ON", "USING", "GROUP", "BY", "HAVING", "ORDER",
    "ASC", "DESC", "NULLS", "FIRST", "LAST", "LIMIT", "OFFSET", "FETCH",
    "NEXT", "ROWS", "ONLY", "TOP", "PERCENT", "WITH", "TIES", "DISTINCT",
    "ALL", "AS", "UNION", "INTERSECT", "EXCEPT", "MINUS",
    # Subqueries
    "IN", "NOT", "EXISTS", "ANY", "SOME",
    # Data Manipulation
    "INSERT", "INTO", "VALUES", "UPDATE", "SET", "DELETE", "TRUNCATE",
    "MERGE", "UPSERT", "RETURNING",
    # Data Definition
    "CREATE", "ALTER", "DROP", "TABLE", "VIEW", "INDEX", "SCHEMA",
    "DATABASE", "SEQUENCE", "TRIGGER", "FUNCTION", "PROCEDURE",
    "PRIMARY", "KEY", "FOREIGN", "REFERENCES", "UNIQUE", "CHECK",
    "DEFAULT", "CONSTRAINT", "CASCADE", "RESTRICT", "NULL",
    "AUTO_INCREMENT", "IDENTITY", "SERIAL", "BIGSERIAL",
    # Data Types
    "INT", "INTEGER", "BIGINT", "SMALLINT", "TINYINT", "FLOAT", "DOUBLE",
    "DECIMAL", "NUMERIC", "REAL", "BOOLEAN", "BOOL", "CHAR", "VARCHAR",
    "TEXT", "CLOB", "BLOB", "BINARY", "VARBINARY", "DATE", "TIME",
    "TIMESTAMP", "DATETIME", "INTERVAL", "JSON", "JSONB", "XML", "UUID",
    "ARRAY", "ENUM", "GEOMETRY", "GEOGRAPHY",
    # Logical
    "AND", "OR", "NOT", "TRUE", "FALSE", "UNKNOWN",
    "IS", "LIKE", "ILIKE", "SIMILAR", "BETWEEN", "CASE", "WHEN", "THEN",
    "ELSE", "END", "COALESCE", "NULLIF", "GREATEST", "LEAST",
    # Aggregate
    "COUNT", "SUM", "AVG", "MIN", "MAX", "ARRAY_AGG", "STRING_AGG",
    "GROUP_CONCAT", "LISTAGG",
    # Window
    "OVER", "PARTITION", "WINDOW", "ROWS", "RANGE", "UNBOUNDED",
    "PRECEDING", "FOLLOWING", "CURRENT", "ROW",
    "ROW_NUMBER", "RANK", "DENSE_RANK", "NTILE", "LAG", "LEAD",
    "FIRST_VALUE", "LAST_VALUE", "NTH_VALUE",
    # Transaction
    "BEGIN", "START", "TRANSACTION", "COMMIT", "ROLLBACK", "SAVEPOINT",
    "RELEASE", "ISOLATION", "LEVEL", "READ", "WRITE", "COMMITTED",
    "UNCOMMITTED", "REPEATABLE", "SERIALIZABLE",
    # Access Control
    "GRANT", "REVOKE", "PRIVILEGES", "TO", "PUBLIC", "ROLE", "USER",
    # Common Functions
    "CAST", "CONVERT", "EXTRACT", "SUBSTRING", "TRIM", "UPPER", "LOWER",
    "LENGTH", "CONCAT", "REPLACE", "NOW", "CURRENT_DATE", "CURRENT_TIME",
    "CURRENT_TIMESTAMP", "CURRENT_USER",
    # Misc
    "EXPLAIN", "ANALYZE", "VERBOSE", "FORMAT", "PLAN", "SHOW", "DESCRIBE",
    "USE", "IF", "ELSE", "ELSEIF", "LOOP", "WHILE", "FOR", "RETURN",
    "DECLARE", "CURSOR", "OPEN", "CLOSE", "FETCH",
    "TEMPORARY", "TEMP", "GLOBAL", "LOCAL", "MATERIALIZED", "RECURSIVE",
    "LATERAL", "NATURAL", "PIVOT", "UNPIVOT", "QUALIFY", "SAMPLE",
})


@dataclass(frozen=True, slots=True)
class Token:
    """
    A SQL token with position information.

    Attributes:
        type: The type of token.
        value: The raw string value of the token.
        line: 1-indexed line number.
        column: 1-indexed column number.
        end_line: End line number.
        end_column: End column number.
    """

    type: TokenType
    value: str
    line: int
    column: int
    end_line: int
    end_column: int

    @property
    def is_keyword(self) -> bool:
        """Check if token is a SQL keyword."""
        return self.type == TokenType.KEYWORD

    @property
    def is_identifier(self) -> bool:
        """Check if token is an identifier."""
        return self.type in (TokenType.IDENTIFIER, TokenType.QUOTED_IDENTIFIER)

    @property
    def is_literal(self) -> bool:
        """Check if token is a literal value."""
        return self.type in (
            TokenType.STRING,
            TokenType.NUMBER,
            TokenType.BOOLEAN,
            TokenType.NULL,
        )

    @property
    def is_whitespace(self) -> bool:
        """Check if token is whitespace."""
        return self.type in (TokenType.WHITESPACE, TokenType.NEWLINE)

    @property
    def is_comment(self) -> bool:
        """Check if token is a comment."""
        return self.type in (TokenType.COMMENT, TokenType.BLOCK_COMMENT)

    @property
    def upper_value(self) -> str:
        """Get uppercase value for case-insensitive comparison."""
        return self.value.upper()


class Tokenizer:
    """
    SQL tokenizer for breaking SQL into tokens.

    This tokenizer handles:
    - Standard SQL keywords and identifiers
    - Quoted identifiers (double quotes, backticks, square brackets)
    - String literals (single quotes, with escape handling)
    - Numbers (integers, floats, scientific notation)
    - Comments (single-line and block)
    - Operators and punctuation

    Example:
        >>> tokenizer = Tokenizer()
        >>> tokens = list(tokenizer.tokenize("SELECT * FROM users"))
        >>> for token in tokens:
        ...     print(f"{token.type.name}: {token.value!r}")
        KEYWORD: 'SELECT'
        WHITESPACE: ' '
        STAR: '*'
        WHITESPACE: ' '
        KEYWORD: 'FROM'
        WHITESPACE: ' '
        IDENTIFIER: 'users'
    """

    # Token patterns (order matters - more specific patterns first)
    _PATTERNS: list[tuple[TokenType, re.Pattern[str]]] = [
        # Comments
        (TokenType.COMMENT, re.compile(r"--[^\n]*")),
        (TokenType.BLOCK_COMMENT, re.compile(r"/\*[\s\S]*?\*/")),

        # Strings
        (TokenType.STRING, re.compile(r"'(?:''|[^'])*'")),  # Single quotes with escape
        (TokenType.STRING, re.compile(r"E'(?:\\'|[^'])*'", re.IGNORECASE)),  # PostgreSQL escape string
        (TokenType.STRING, re.compile(r"\$\$[\s\S]*?\$\$")),  # Dollar quoting

        # Quoted identifiers
        (TokenType.QUOTED_IDENTIFIER, re.compile(r'"(?:""|[^"])*"')),  # Double quotes
        (TokenType.QUOTED_IDENTIFIER, re.compile(r"`(?:``|[^`])*`")),  # Backticks (MySQL)
        (TokenType.QUOTED_IDENTIFIER, re.compile(r"\[(?:\]\]|[^\]])*\]")),  # Square brackets (SQL Server)

        # Numbers
        (TokenType.NUMBER, re.compile(r"\d+\.?\d*(?:[eE][+-]?\d+)?")),  # Integer, float, scientific
        (TokenType.NUMBER, re.compile(r"\.\d+(?:[eE][+-]?\d+)?")),  # .5, .5e10

        # Placeholders
        (TokenType.PLACEHOLDER, re.compile(r"\$\d+")),  # PostgreSQL $1, $2
        (TokenType.PLACEHOLDER, re.compile(r":\w+")),  # Named :param
        (TokenType.PLACEHOLDER, re.compile(r"\?")),  # Positional ?
        (TokenType.PLACEHOLDER, re.compile(r"@\w+")),  # SQL Server @param
        (TokenType.PLACEHOLDER, re.compile(r"%\(\w+\)s")),  # Python %(name)s
        (TokenType.PLACEHOLDER, re.compile(r"%s")),  # Python %s

        # Double-character operators
        (TokenType.DOUBLE_COLON, re.compile(r"::")),  # PostgreSQL cast
        (TokenType.COMPARISON, re.compile(r"<>|!=|>=|<=|<=>|!<|!>")),
        (TokenType.LOGICAL, re.compile(r"\|\||&&")),
        (TokenType.ARITHMETIC, re.compile(r"\*\*|<<|>>")),

        # Single-character tokens
        (TokenType.LPAREN, re.compile(r"\(")),
        (TokenType.RPAREN, re.compile(r"\)")),
        (TokenType.COMMA, re.compile(r",")),
        (TokenType.SEMICOLON, re.compile(r";")),
        (TokenType.DOT, re.compile(r"\.")),
        (TokenType.COLON, re.compile(r":")),
        (TokenType.STAR, re.compile(r"\*")),
        (TokenType.COMPARISON, re.compile(r"[<>=]")),
        (TokenType.ARITHMETIC, re.compile(r"[+\-/%^&|~]")),

        # Whitespace
        (TokenType.NEWLINE, re.compile(r"\n")),
        (TokenType.WHITESPACE, re.compile(r"[ \t\r]+")),

        # Identifiers (must be after keywords check)
        (TokenType.IDENTIFIER, re.compile(r"[a-zA-Z_][a-zA-Z0-9_]*")),
    ]

    def __init__(self, *, skip_whitespace: bool = False, skip_comments: bool = False) -> None:
        """
        Initialize the tokenizer.

        Args:
            skip_whitespace: If True, whitespace tokens are not yielded.
            skip_comments: If True, comment tokens are not yielded.
        """
        self.skip_whitespace = skip_whitespace
        self.skip_comments = skip_comments

    def tokenize(self, sql: str) -> Iterator[Token]:
        """
        Tokenize a SQL string.

        Args:
            sql: The SQL string to tokenize.

        Yields:
            Token objects for each token in the input.
        """
        pos = 0
        line = 1
        col = 1
        length = len(sql)

        while pos < length:
            matched = False

            for token_type, pattern in self._PATTERNS:
                match = pattern.match(sql, pos)
                if match:
                    value = match.group(0)
                    end_pos = match.end()

                    # Calculate end position
                    end_line = line + value.count("\n")
                    if "\n" in value:
                        end_col = len(value) - value.rfind("\n")
                    else:
                        end_col = col + len(value)

                    # Check if identifier is actually a keyword
                    actual_type = token_type
                    if token_type == TokenType.IDENTIFIER:
                        upper_val = value.upper()
                        if upper_val in ("TRUE", "FALSE"):
                            actual_type = TokenType.BOOLEAN
                        elif upper_val == "NULL":
                            actual_type = TokenType.NULL
                        elif upper_val in SQL_KEYWORDS:
                            actual_type = TokenType.KEYWORD

                    # Skip if configured
                    should_skip = False
                    if self.skip_whitespace and actual_type in (
                        TokenType.WHITESPACE,
                        TokenType.NEWLINE,
                    ):
                        should_skip = True
                    if self.skip_comments and actual_type in (
                        TokenType.COMMENT,
                        TokenType.BLOCK_COMMENT,
                    ):
                        should_skip = True

                    if not should_skip:
                        yield Token(
                            type=actual_type,
                            value=value,
                            line=line,
                            column=col,
                            end_line=end_line,
                            end_column=end_col,
                        )

                    # Update position
                    pos = end_pos
                    line = end_line
                    col = end_col if "\n" not in value else end_col

                    matched = True
                    break

            if not matched:
                # Unknown character
                char = sql[pos]
                yield Token(
                    type=TokenType.UNKNOWN,
                    value=char,
                    line=line,
                    column=col,
                    end_line=line,
                    end_column=col + 1,
                )
                pos += 1
                col += 1

        # EOF token
        yield Token(
            type=TokenType.EOF,
            value="",
            line=line,
            column=col,
            end_line=line,
            end_column=col,
        )

    def get_tokens(self, sql: str) -> list[Token]:
        """
        Get all tokens as a list.

        Args:
            sql: The SQL string to tokenize.

        Returns:
            List of all tokens.
        """
        return list(self.tokenize(sql))

    def get_significant_tokens(self, sql: str) -> list[Token]:
        """
        Get tokens excluding whitespace and comments.

        Args:
            sql: The SQL string to tokenize.

        Returns:
            List of significant tokens only.
        """
        return [
            t for t in self.tokenize(sql)
            if not t.is_whitespace and not t.is_comment and t.type != TokenType.EOF
        ]


def tokenize(sql: str, *, skip_whitespace: bool = True) -> list[Token]:
    """
    Convenience function to tokenize SQL.

    Args:
        sql: The SQL string to tokenize.
        skip_whitespace: Whether to skip whitespace tokens.

    Returns:
        List of tokens.

    Example:
        >>> tokens = tokenize("SELECT * FROM users")
        >>> [t.value for t in tokens]
        ['SELECT', '*', 'FROM', 'users']
    """
    tokenizer = Tokenizer(skip_whitespace=skip_whitespace, skip_comments=True)
    return [t for t in tokenizer.tokenize(sql) if t.type != TokenType.EOF]