import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional


class IssueSeverity(Enum):
    """Severity levels for detected issues"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class DetectedIssue:
    """Represents a detected SQL issue"""
    issue_type: str
    query: str
    description: str
    fix: str
    impact: str
    severity: IssueSeverity
    line_number: Optional[int] = None


class QueryDetector:
    """
    SQL Query Pattern Detector
    Analyzes SQL queries for common anti-patterns, performance issues,
    and potential bugs without executing them.
    Example:
        >>> detector = QueryDetector()
        >>> issues = detector.analyze("SELECT * FROM users WHERE name LIKE '%john%'")
        >>> for issue in issues:
        ...     print(f"{issue.issue_type}: {issue.fix}")
    """

    def __init__(self)-> None:
        """Initialize the detector with pattern definitions"""
        self._patterns = self._compile_patterns()
        self.detectors = self._get_all_detectors()

    def _compile_patterns(self) -> dict[str, re.Pattern]:
        """Pre-compile all regex patterns for performance."""
        return {
            'select_star': re.compile(r'SELECT\s+\*', re.IGNORECASE),
            'missing_where': re.compile(r'(UPDATE|DELETE)(\s+FROM)?\s+\w+(\s+SET)?', re.IGNORECASE),
            'non_sargable': re.compile(r'WHERE\s+(YEAR|MONTH|DAY|UPPER|LOWER)\s*\([^)]+\)\s*=', re.IGNORECASE),
            'implicit_conversion': re.compile(r"WHERE\s+\w*(name|email|code|status)\w*\s*=\s*\d+", re.IGNORECASE),
            'cartesian_product': re.compile(r'FROM\s+\w+\s*,\s*\w+', re.IGNORECASE),
            'n_plus_1': re.compile(r'SELECT.*FROM.*WHERE\s+\w+_id\s*=\s*\?', re.IGNORECASE),
            'correlated_subquery': re.compile(r'SELECT.*\(SELECT.*FROM.*WHERE.*=.*\w+\.\w+', re.IGNORECASE),
            'or_prevents_index': re.compile(r'WHERE.*\w+\s*=.*\sOR\s+\w+\s*=', re.IGNORECASE),
            'offset_pagination': re.compile(r'OFFSET\s+(\d+)', re.IGNORECASE),
            'distinct_unnecessary': re.compile(r'SELECT\s+DISTINCT\s+\w*id\w*', re.IGNORECASE),
            'huge_in_list': re.compile(r'IN\s*\(([^)]+)\)', re.IGNORECASE),
            'leading_wildcard': re.compile(r'LIKE\s+[\'"]%', re.IGNORECASE),
            'count_star_exists': re.compile(r'COUNT\s*\(\s*\*\s*\)\s*>\s*0', re.IGNORECASE),
            'not_in_nullable': re.compile(r'NOT\s+IN\s*\(\s*SELECT', re.IGNORECASE),
            'no_limit_exists': re.compile(r'EXISTS\s*\(\s*SELECT\s+(?!.*LIMIT)', re.IGNORECASE),
            'floating_point_equals': re.compile(r'(price|amount|total|cost|value)\s*=\s*\d+\.\d+', re.IGNORECASE),
            'null_comparison': re.compile(r'=\s*NULL|!=\s*NULL', re.IGNORECASE),
            'function_on_column': re.compile(r'WHERE.*(LOWER|UPPER|TRIM|SUBSTRING|DATE|YEAR|MONTH)\s*\(\s*(id|email|user_id|created_at)', re.IGNORECASE),
            'having_no_aggregates': re.compile(r'HAVING(?!\s+COUNT|\s+SUM|\s+AVG|\s+MAX|\s+MIN)', re.IGNORECASE),
            'union_missing_all': re.compile(r'UNION(?!\s+ALL)', re.IGNORECASE),
            'subquery_select_list': re.compile(r'SELECT.*,.*\(SELECT', re.IGNORECASE),
            'between_timestamps': re.compile(r'BETWEEN.*\d{4}-\d{2}-\d{2}.*AND.*\d{4}-\d{2}-\d{2}', re.IGNORECASE),
            'case_in_where': re.compile(r'WHERE.*CASE\s+WHEN', re.IGNORECASE),
            'offset_no_order': re.compile(r'OFFSET\s+\d+(?!.*ORDER\s+BY)', re.IGNORECASE),
            'like_no_wildcard': re.compile(r'LIKE\s+["\'][^%_]+["\']', re.IGNORECASE),
            'order_by_ordinal': re.compile(r'ORDER\s+BY\s+\d+', re.IGNORECASE),
        }


    def analyze(self, queries: str | list[str]) -> list[DetectedIssue]:
        """
        Analyze SQL query/queries for issues

        Args:
            queries: Single query string or list of queries

        Returns:
            List of DetectedIssue objects
        """
        if isinstance(queries, str):
            queries = [queries]

        all_issues: list[DetectedIssue] = []

        for query in queries:
            # Clean query for analysis
            clean_query = self._normalize_query(query)

            # Run all detectors
            for _detector_name, detector_func in self.detectors.items():
                result = detector_func(clean_query, query)
                if result:
                    all_issues.append(result)

            # Extra rule: detect OR conditions in WHERE clause
            if re.search(r"\bWHERE\b.*\bOR\b", clean_query, re.IGNORECASE | re.DOTALL):
                all_issues.append(
                    DetectedIssue(
                        issue_type="OR Prevents Index",
                        query=query,
                        description="OR conditions in WHERE can prevent index usage",
                        fix="Rewrite query to avoid OR, use UNION or separate conditions",
                        impact="Indexes may not be used, causing full table scans",
                        severity=IssueSeverity.MEDIUM,
                        line_number=None,
                    )
                )

        return all_issues


    def _normalize_query(self, query: str) -> str:
        """Normalize query for consistent pattern matching"""
        # Remove extra whitespace
        query = ' '.join(query.split())
        # Remove comments
        query = re.sub(r'--.*$', '', query, flags=re.MULTILINE)
        query = re.sub(r'/\*.*?\*/', '', query, flags=re.DOTALL)
        return query.strip()

    def _get_all_detectors(self) -> dict[str, Any]:
        """Map all detector methods"""
        return {
            'select_star': self._detect_select_star,
            'missing_where': self._detect_missing_where_update_delete,
            'non_sargable': self._detect_non_sargable,
            'implicit_conversion': self._detect_implicit_conversion,
            'cartesian_product': self._detect_cartesian_product,
            'n_plus_1': self._detect_n_plus_1_pattern,
            'correlated_subquery': self._detect_correlated_subquery,
            'or_prevents_index': self._detect_or_prevents_index,
            'offset_pagination': self._detect_offset_pagination,
            'distinct_unnecessary': self._detect_unnecessary_distinct,
            'in_clause_large': self._detect_huge_in_list,
            'like_leading_wildcard': self._detect_leading_wildcard,
            'count_star_exists': self._detect_count_star_exists,
            'not_in_null': self._detect_not_in_nullable,
            'missing_limit_exists': self._detect_no_limit_in_exists,
            'floating_point_equals': self._detect_floating_point_equality,
            'null_comparison': self._detect_null_comparison_with_equal,
            'function_on_column': self._detect_function_on_indexed_column,
            'having_no_aggregates': self._detect_having_instead_of_where,
            'union_missing_all': self._detect_union_missing_all,
            'subquery_select_list': self._detect_subquery_in_select_list,
            'between_timestamps': self._detect_between_with_timestamps,
            'case_in_where': self._detect_case_in_where,
            'offset_no_order': self._detect_offset_without_order,
            'like_no_wildcard': self._detect_like_without_wildcard,
            'multiple_wildcards': self._detect_multiple_wildcards,
            'order_by_ordinal': self._detect_order_by_ordinal,
        }

    # Core Detector Methods

    def _detect_select_star(self, clean_query: str, original_query: str) -> Optional[DetectedIssue]:
        """Detect SELECT * usage"""
        if self._patterns['select_star'].search(clean_query):
            return DetectedIssue(
                issue_type="SELECT * Usage",
                query=original_query,
                description="Query retrieves all columns unnecessarily",
                fix="Specify only needed columns",
                impact="50-90% less data transfer, enables covering indexes",
                severity=IssueSeverity.MEDIUM
            )
        return None

    def _detect_missing_where_update_delete(self, clean_query: str, original_query: str) -> Optional[DetectedIssue]:
        """Detect UPDATE/DELETE without WHERE clause"""
        if self._patterns['missing_where'].match(clean_query) and 'WHERE' not in clean_query.upper():
                return DetectedIssue(
                    issue_type="Missing WHERE in UPDATE/DELETE",
                    query=original_query,
                    description="UPDATE/DELETE without WHERE affects entire table",
                    fix="Add WHERE clause or use TRUNCATE if intentional",
                    impact="Can delete/update entire table accidentally",
                    severity=IssueSeverity.CRITICAL
                )
        return None

    def _detect_non_sargable(self, clean_query: str, original_query: str) -> Optional[DetectedIssue]:
        """Detect non-SARGable WHERE clauses (prevents index usage)"""
        if self._patterns['non_sargable'].search(clean_query):
            return DetectedIssue(
                issue_type="Non-SARGable WHERE",
                query=original_query,
                description="WHERE clause prevents index usage",
                fix="Use date range or functional index",
                impact="Full table scan instead of index seek",
                severity=IssueSeverity.HIGH
            )
        return None




    def _detect_implicit_conversion(self, clean_query: str, original_query: str) -> Optional[DetectedIssue]:
        """Detect implicit type conversions"""
        if self._patterns['implicit_conversion'].search(clean_query):
            return DetectedIssue(
                issue_type="Implicit Type Conversion",
                query=original_query,
                description="Comparing string column to number forces conversion",
                fix="Use proper quotes for string values",
                impact="Prevents index usage, causes full table scan",
                severity=IssueSeverity.HIGH
            )
        return None

    def _detect_cartesian_product(self, clean_query: str, original_query: str) -> Optional[DetectedIssue]:
        """Detect accidental cartesian products"""
        if self._patterns['cartesian_product'].search(clean_query) and not re.search(r'WHERE|JOIN', clean_query, re.IGNORECASE):
                return DetectedIssue(
                    issue_type="Cartesian Product",
                    query=original_query,
                    description="Multiple tables without JOIN condition",
                    fix="Add proper JOIN conditions",
                    impact="Result set explodes exponentially",
                    severity=IssueSeverity.CRITICAL
                )
        return None

    def _detect_n_plus_1_pattern(self, clean_query: str, original_query: str) -> Optional[DetectedIssue]:
        """Detect potential N+1 query patterns"""
        # This would need multiple queries to detect properly
        # For now, detect subqueries that look like N+1
        if self._patterns['n_plus_1'].search(clean_query):
            return DetectedIssue(
                issue_type="Potential N+1 Pattern",
                query=original_query,
                description="Query pattern suggests N+1 issue when in loop",
                fix="Use JOIN or WHERE IN batch query",
                impact="Network roundtrips multiply by N",
                severity=IssueSeverity.HIGH
            )
        return None

    def _detect_correlated_subquery(self, clean_query: str, original_query: str) -> Optional[DetectedIssue]:
        """Detect correlated subqueries"""
        if self._patterns['correlated_subquery'].search(clean_query):
            return DetectedIssue(
                issue_type="Correlated Subquery",
                query=original_query,
                description="Subquery executes once per row",
                fix="Rewrite as JOIN or pre-calculate values",
                impact="O(n²) performance degradation",
                severity=IssueSeverity.HIGH
            )
        return None

    def _detect_or_prevents_index(self, clean_query: str, original_query: str) -> Optional[DetectedIssue]:
        """Detect OR conditions preventing index usage"""
        if self._patterns['or_prevents_index'].search(clean_query):
            return DetectedIssue(
                issue_type="OR Prevents Index",
                query=original_query,
                description="OR across different columns prevents index usage",
                fix="Use UNION or redesign query logic",
                impact="Forces full table scan",
                severity=IssueSeverity.MEDIUM
            )
        return None

    def _detect_offset_pagination(self, clean_query: str, original_query: str) -> Optional[DetectedIssue]:
        """Detect large OFFSET values"""
        match = self._patterns['offset_pagination'].search(clean_query)

        if match:
            offset = int(match.group(1))
            if offset > 1000:
                return DetectedIssue(
                    issue_type="Large OFFSET Pagination",
                    query=original_query,
                    description=f"OFFSET {offset} reads and discards {offset} rows",
                    fix="Use cursor-based pagination with WHERE id > last_id",
                    impact="Performance degrades linearly with offset",
                    severity=IssueSeverity.HIGH
                )
        return None

    def _detect_unnecessary_distinct(self, clean_query: str, original_query: str) -> Optional[DetectedIssue]:
        """Detect DISTINCT on unique columns"""
        if self._patterns['distinct_unnecessary'].search(clean_query):
            return DetectedIssue(
                issue_type="Unnecessary DISTINCT",
                query=original_query,
                description="DISTINCT on already-unique column",
                fix="Remove DISTINCT for unique columns",
                impact="Adds unnecessary sorting overhead",
                severity=IssueSeverity.LOW
            )
        return None

    def _detect_huge_in_list(self, clean_query: str, original_query: str) -> Optional[DetectedIssue]:
        """Detect IN clauses with too many values"""
        in_match = self._patterns['huge_in_list'].search(clean_query)
        if in_match:
            values = in_match.group(1).split(',')
            if len(values) > 50:
                return DetectedIssue(
                    issue_type="Massive IN List",
                    query=original_query,
                    description=f"IN clause with {len(values)} values",
                    fix="Use temp table JOIN instead",
                    impact="Query parser overhead, plan cache bloat",
                    severity=IssueSeverity.HIGH
                )
        return None

    def _detect_leading_wildcard(self, clean_query: str, original_query: str) -> Optional[DetectedIssue]:
        """Detect leading wildcards in LIKE"""
        if self._patterns['leading_wildcard'].search(clean_query):
            return DetectedIssue(
                issue_type="Leading Wildcard",
                query=original_query,
                description="Leading % prevents index usage",
                fix="Use full-text search or redesign query",
                impact="Forces full table scan",
                severity=IssueSeverity.HIGH
            )
        return None

    def _detect_count_star_exists(self, clean_query: str, original_query: str) -> Optional[DetectedIssue]:
        """Detect COUNT(*) for existence check"""
        if self._patterns['count_star_exists'].search(clean_query):
            return DetectedIssue(
                issue_type="COUNT(*) for Existence",
                query=original_query,
                description="Using COUNT(*) to check if rows exist",
                fix="Use EXISTS instead",
                impact="Counts all rows instead of stopping at first",
                severity=IssueSeverity.MEDIUM
            )
        return None

    def _detect_not_in_nullable(self, clean_query: str, original_query: str) -> Optional[DetectedIssue]:
        """Detect NOT IN with subquery (NULL trap)"""
        if self._patterns['not_in_nullable'].search(clean_query):
            return DetectedIssue(
                issue_type="NOT IN with NULLable",
                query=original_query,
                description="NOT IN with subquery fails if any NULL values",
                fix="Use NOT EXISTS instead",
                impact="Query returns no results if subquery contains NULL",
                severity=IssueSeverity.HIGH
            )
        return None

    def _detect_no_limit_in_exists(self, clean_query: str, original_query: str) -> Optional[DetectedIssue]:
        """Detect EXISTS without LIMIT"""
        if self._patterns['no_limit_exists'].search(clean_query):
            return DetectedIssue(
                issue_type="EXISTS without LIMIT",
                query=original_query,
                description="EXISTS checks all rows unnecessarily",
                fix="Add LIMIT 1 to EXISTS subquery",
                impact="Continues scanning after first match",
                severity=IssueSeverity.LOW
            )
        return None

    def _detect_floating_point_equality(self, clean_query: str, original_query: str) -> Optional[DetectedIssue]:
        """Detect floating point equality comparison"""
        if self._patterns['floating_point_equals'].search(clean_query):
            return DetectedIssue(
                issue_type="Floating Point Equality",
                query=original_query,
                description="Exact equality on floating point values",
                fix="Use range comparison or DECIMAL type",
                impact="May miss values due to precision issues",
                severity=IssueSeverity.MEDIUM
            )
        return None

    def _detect_null_comparison_with_equal(self, clean_query: str, original_query: str) -> Optional[DetectedIssue]:
        """Detect = NULL or != NULL"""
        #print(f"DEBUG: Checking query for NULL: {clean_query}")
        if self._patterns['null_comparison'].search(clean_query):
            #print("DEBUG: Found NULL comparison!")
            return DetectedIssue(
                issue_type="NULL Comparison Error",
                query=original_query,
                description="Using = or != with NULL always returns UNKNOWN",
                fix="Use IS NULL or IS NOT NULL",
                impact="Condition never matches any rows",
                severity=IssueSeverity.CRITICAL
            )
        return None

    def _detect_function_on_indexed_column(self, clean_query: str, original_query: str) -> Optional[DetectedIssue]:
        """Detect functions on potentially indexed columns"""
        if self._patterns['function_on_column'].search(clean_query):
            return DetectedIssue(
                issue_type="Function on Indexed Column",
                query=original_query,
                description="Function on column prevents index usage",
                fix="Create functional index or rewrite condition",
                impact="Full table scan instead of index seek",
                severity=IssueSeverity.HIGH
            )
        return None

    def _detect_having_instead_of_where(self, clean_query: str, original_query: str) -> Optional[DetectedIssue]:
        """Detect HAVING used for row filtering"""
        if self._patterns['having_no_aggregates'].search(clean_query) and 'WHERE' not in clean_query.upper():
                return DetectedIssue(
                    issue_type="HAVING Instead of WHERE",
                    query=original_query,
                    description="HAVING filters after grouping",
                    fix="Use WHERE for row filtering before GROUP BY",
                    impact="Processes all rows before filtering",
                    severity=IssueSeverity.MEDIUM
                )
        return None

    def _detect_union_missing_all(self, clean_query: str, original_query: str) -> Optional[DetectedIssue]:
        """Detect UNION without ALL"""
        if self._patterns['union_missing_all'].search(clean_query):
            return DetectedIssue(
                issue_type="UNION Missing ALL",
                query=original_query,
                description="UNION performs unnecessary deduplication",
                fix="Use UNION ALL if duplicates are acceptable",
                impact="Adds expensive DISTINCT operation",
                severity=IssueSeverity.MEDIUM
            )
        return None

    def _detect_subquery_in_select_list(self, clean_query: str, original_query: str) -> Optional[DetectedIssue]:
        """Detect subqueries in SELECT list"""
        if self._patterns['subquery_select_list'].search(clean_query):
            return DetectedIssue(
                issue_type="Subquery in SELECT List",
                query=original_query,
                description="Subquery executes for every row",
                fix="Convert to JOIN or pre-calculate",
                impact="O(n) subquery executions",
                severity=IssueSeverity.HIGH
            )
        return None

    def _detect_between_with_timestamps(self, clean_query: str, original_query: str) -> Optional[DetectedIssue]:
        """Detect BETWEEN with date boundaries"""
        if self._patterns['between_timestamps'].search(clean_query):
            return DetectedIssue(
                issue_type="BETWEEN with Timestamps",
                query=original_query,
                description="BETWEEN with dates may miss end-of-day records",
                fix="Use >= start AND < end+1 day",
                impact="Misses records with time components",
                severity=IssueSeverity.MEDIUM
            )
        return None

    def _detect_case_in_where(self, clean_query: str, original_query: str) -> Optional[DetectedIssue]:
        """Detect CASE expressions in WHERE"""
        if self._patterns['case_in_where'].search(clean_query):
            return DetectedIssue(
                issue_type="CASE in WHERE Clause",
                query=original_query,
                description="Complex CASE in WHERE prevents optimization",
                fix="Simplify logic or move to application",
                impact="Prevents index usage and predicate pushdown",
                severity=IssueSeverity.MEDIUM
            )
        return None

    def _detect_offset_without_order(self, clean_query: str, original_query: str) -> Optional[DetectedIssue]:
        """Detect OFFSET without ORDER BY"""
        if self._patterns['offset_no_order'].search(clean_query):
            return DetectedIssue(
                issue_type="OFFSET without ORDER BY",
                query=original_query,
                description="OFFSET without ORDER BY returns random results",
                fix="Add ORDER BY for deterministic results",
                impact="Different results each execution",
                severity=IssueSeverity.HIGH
            )
        return None

    def _detect_like_without_wildcard(self, clean_query: str, original_query: str) -> Optional[DetectedIssue]:
        """Detect LIKE without wildcards"""
        if self._patterns['like_no_wildcard'].search(clean_query):
            return DetectedIssue(
                issue_type="LIKE without Wildcards",
                query=original_query,
                description="LIKE without wildcards should be =",
                fix="Use = for exact matches",
                impact="Slightly slower than equality check",
                severity=IssueSeverity.LOW
            )
        return None

    def _detect_multiple_wildcards(self, clean_query: str, original_query: str) -> Optional[DetectedIssue]:
        """Detect multiple wildcards"""
        wildcard_count = len(re.findall(r'%', clean_query))
        if wildcard_count > 2:
            return DetectedIssue(
                issue_type="Multiple Wildcards",
                query=original_query,
                description=f"{wildcard_count} wildcards cause exponential scanning",
                fix="Use full-text search for complex patterns",
                impact="Exponential performance degradation",
                severity=IssueSeverity.HIGH
            )
        return None

    def _detect_order_by_ordinal(self, clean_query: str, original_query: str) -> Optional[DetectedIssue]:
        """Detect ORDER BY with ordinal positions"""
        if self._patterns['order_by_ordinal'].search(clean_query):
            return DetectedIssue(
                issue_type="ORDER BY Ordinal",
                query=original_query,
                description="ORDER BY position number is fragile",
                fix="Use column names explicitly",
                impact="Breaks when SELECT list changes",
                severity=IssueSeverity.LOW
            )
        return None


# Helper function for batch analysis
def analyze_queries(queries: list[str]) -> list[DetectedIssue]:
    """
    Convenience function to analyze multiple queries
    Args:
        queries: List of SQL queries to analyze
    Returns:
        List of all detected issues
    """
    detector = QueryDetector()
    return detector.analyze(queries)
