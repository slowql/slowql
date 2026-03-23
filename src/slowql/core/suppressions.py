# slowql/src/slowql/core/suppressions.py
"""
Inline suppression directive parser for SlowQL.

Parses SQL source text for ``-- slowql-*`` directives and constructs a
:class:`SuppressionMap` that can answer "is issue X at line Y suppressed?"
without any dependency on the main parser or rule logic.

Supported directives
--------------------
- ``-- slowql-disable-line [RULE-ID[, RULE-ID …]]``
    Suppress rules on the same line as the comment.

- ``-- slowql-disable-next-line [RULE-ID[, RULE-ID …]]``
    Suppress rules on the next non-blank, non-pure-comment line.

- ``-- slowql-disable [RULE-ID[, RULE-ID …]]``
    Open a suppression block.  All following lines are suppressed until a
    matching ``-- slowql-enable`` directive (or EOF).

- ``-- slowql-enable [RULE-ID[, RULE-ID …]]``
    Close a previously opened suppression block.

- ``-- slowql-disable-file [RULE-ID[, RULE-ID …]]``
    Suppress rules for the **entire file**, regardless of where the directive
    appears.

Rule ID matching
----------------
- An exact rule ID matches only that rule (``PERF-SCAN-001``).
- A prefix match is supported: ``PERF-SCAN`` matches ``PERF-SCAN-001``.
- Omitting the rule ID (bare directive) matches **all** rules.
- Multiple rule IDs may be comma-separated on a single directive.
- Matching is case-insensitive.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Final

# ---------------------------------------------------------------------------
# Sentinel used internally to represent "suppress all rules"
# ---------------------------------------------------------------------------
_ALL: Final[str] = "__ALL__"

# ---------------------------------------------------------------------------
# Regex that matches the directive portion of a line comment.
# Group 1: directive keyword (disable-line, disable-next-line, disable-file,
#           disable, enable)
# Group 2: optional rule-id list (may be absent → suppress all)
# ---------------------------------------------------------------------------
_DIRECTIVE_RE: Final[re.Pattern[str]] = re.compile(
    r"--\s*slowql-(disable-line|disable-next-line|disable-file|disable|enable)"
    r"(?:\s+([^\n]*))?",
    re.IGNORECASE,
)


def _parse_rule_ids(raw: str | None) -> frozenset[str]:
    """
    Parse comma-separated rule IDs from a raw string.

    Returns a frozenset containing normalised (upper-case) rule IDs.
    If *raw* is None or blank, returns ``frozenset({_ALL})`` — meaning the
    directive applies to every rule.
    """
    if not raw or not raw.strip():
        return frozenset({_ALL})
    return frozenset(r.strip().upper() for r in raw.split(",") if r.strip())


def _rule_matches(suppressed_ids: frozenset[str], query_id: str) -> bool:
    """
    Return ``True`` when *query_id* is covered by *suppressed_ids*.

    Matching rules:
    - ``_ALL`` in suppressed_ids → always True
    - exact uppercase match
    - prefix match: ``suppressed_id`` is a prefix of ``query_id``
      when the next character in ``query_id`` after the prefix is ``-``
    """
    upper = query_id.upper()
    if _ALL in suppressed_ids:
        return True
    if upper in suppressed_ids:
        return True
    for sid in suppressed_ids:
        if upper.startswith(sid) and (
            len(upper) == len(sid) or upper[len(sid)] == "-"
        ):
            return True
    return False


# ---------------------------------------------------------------------------
# SuppressionMap
# ---------------------------------------------------------------------------

@dataclass
class SuppressionMap:
    """
    An immutable-ish view of all suppression directives found in a SQL source.

    Use :func:`parse_suppressions` to construct an instance.
    """

    # Rules suppressed for the entire file (regardless of line)
    _file_rules: frozenset[str] = field(default_factory=frozenset)

    # Rules suppressed on a specific line: {1-indexed line → frozenset[rule_ids]}
    _line_rules: dict[int, frozenset[str]] = field(default_factory=dict)

    # Block suppressions: list of (start_line, end_line_or_None, frozenset[rule_ids])
    # end_line is None when no matching enable was found (open block → suppress to EOF)
    _block_ranges: list[tuple[int, int | None, frozenset[str]]] = field(
        default_factory=list
    )

    def is_suppressed(self, line: int, rule_id: str) -> bool:
        """
        Return ``True`` if *rule_id* is suppressed on *line*.

        Args:
            line: 1-indexed line number of the issue.
            rule_id: The rule identifier to check (e.g. ``"PERF-SCAN-001"``).
        """
        if line <= 0:
            return False

        # File-level check
        if _rule_matches(self._file_rules, rule_id):
            return True

        # Exact-line check
        if line in self._line_rules and _rule_matches(self._line_rules[line], rule_id):
            return True

        # Block range check
        for start, end, ids in self._block_ranges:
            if line < start:
                continue
            if end is not None and line > end:
                continue
            if _rule_matches(ids, rule_id):
                return True

        return False

    def __repr__(self) -> str:
        return (
            f"SuppressionMap("
            f"file_rules={self._file_rules!r}, "
            f"line_rules_count={len(self._line_rules)}, "
            f"block_ranges_count={len(self._block_ranges)})"
        )


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def parse_suppressions(sql: str) -> SuppressionMap:
    """
    Parse *sql* for ``-- slowql-*`` directives and return a :class:`SuppressionMap`.

    The function scans the SQL text line-by-line, skipping string literals so
    that a directive embedded inside a quoted string is never interpreted.

    Args:
        sql: Raw SQL source text (may contain multiple statements).

    Returns:
        A :class:`SuppressionMap` representing all suppression directives found.
    """
    if not sql:
        return SuppressionMap()

    lines = sql.splitlines()

    file_rules: set[str] = set()
    line_rules: dict[int, frozenset[str]] = {}
    # open_blocks: rule_id → start_line (1-indexed)
    open_blocks: dict[str, int] = {}
    closed_ranges: list[tuple[int, int | None, frozenset[str]]] = []

    # pending_next_line: accumulated rule sets waiting for the next code line
    pending_next_line: list[frozenset[str]] = []

    for lineno, raw_line in enumerate(lines, start=1):
        comment_text = _extract_comment(raw_line)

        if comment_text:
            m = _DIRECTIVE_RE.search(comment_text)
            if m:
                directive = m.group(1).lower()
                rule_ids = _parse_rule_ids(m.group(2))
                _apply_directive(
                    directive,
                    rule_ids,
                    lineno,
                    file_rules,
                    line_rules,
                    open_blocks,
                    closed_ranges,
                    pending_next_line,
                )

        # Resolve pending disable-next-line directives
        if pending_next_line and _is_code_line(raw_line):
            merged: frozenset[str] = frozenset()
            for rule_set in pending_next_line:
                merged = merged | rule_set
            existing = line_rules.get(lineno, frozenset())
            line_rules[lineno] = existing | merged
            pending_next_line.clear()

    # Close any still-open blocks (suppression runs to EOF)
    for rid, start in open_blocks.items():
        closed_ranges.append((start, None, frozenset({rid})))

    return SuppressionMap(
        _file_rules=frozenset(file_rules),
        _line_rules=line_rules,
        _block_ranges=closed_ranges,
    )


def _apply_directive(
    directive: str,
    rule_ids: frozenset[str],
    lineno: int,
    file_rules: set[str],
    line_rules: dict[int, frozenset[str]],
    open_blocks: dict[str, int],
    closed_ranges: list[tuple[int, int | None, frozenset[str]]],
    pending_next_line: list[frozenset[str]],
) -> None:
    """Apply a single parsed directive to the accumulated suppression state."""
    if directive == "disable-line":
        existing = line_rules.get(lineno, frozenset())
        line_rules[lineno] = existing | rule_ids

    elif directive == "disable-next-line":
        pending_next_line.append(rule_ids)

    elif directive == "disable-file":
        file_rules |= rule_ids

    elif directive == "disable":
        for rid in rule_ids:
            open_blocks[rid] = lineno + 1  # block starts AFTER directive line

    elif directive == "enable":
        for rid in rule_ids:
            if rid in open_blocks:
                start = open_blocks.pop(rid)
                end = lineno - 1
                if start <= end:
                    closed_ranges.append((start, end, frozenset({rid})))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_code_line(line: str) -> bool:
    """
    Return ``True`` if *line* contains non-whitespace content that is not
    purely a SQL line comment.

    Used to advance past blank lines when resolving ``disable-next-line``.
    """
    stripped = line.strip()
    if not stripped:
        return False
    return not stripped.startswith("--")


def _extract_comment(line: str) -> str:
    """
    Extract the SQL line-comment portion of *line*, skipping string literals.

    Returns the comment text (including ``--``) or an empty string if the line
    contains no line comment outside a string literal.
    """
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        if ch in ("'", '"', "`"):
            # Skip over the string literal
            i = _skip_quoted(line, i, n, ch)
        elif ch == "-" and i + 1 < n and line[i + 1] == "-":
            # Found a line comment; return everything from here
            return line[i:]
        else:
            i += 1
    return ""


def _skip_quoted(s: str, start: int, n: int, quote: str) -> int:
    """Advance past a quoted identifier or string literal."""
    i = start + 1
    while i < n:
        if s[i] == quote:
            if i + 1 < n and s[i + 1] == quote:  # escaped quote
                i += 2
                continue
            return i + 1
        i += 1
    return n
