"""
SLOWQL Query Analyzer

Coordinates the analysis of SQL queries for performance issues,
anti-patterns, and potential bugs. Provides both raw results
and formatted output.
"""

from typing import List, Dict, Any, Union, Optional, Tuple
import pandas as pd
from datetime import datetime
from concurrent.futures import ProcessPoolExecutor
from .detector import QueryDetector, DetectedIssue

import time
from slowql.metrics import AnalysisMetrics



class QueryAnalyzer:
    """
    SQL Query Analyzer

    Provides methods to analyze SQL queries for performance issues,
    anti-patterns, and potential bugs. Supports sequential and parallel
    execution, and can return results as either a pandas DataFrame or
    a list of DetectedIssue objects.
    """


    def __init__(self, verbose: bool = True) -> None:
        """
        Initialize QueryAnalyzer.

        Args:
            verbose: Whether to print analysis progress
        """
        self.detector: QueryDetector = QueryDetector()
        self.verbose: bool = verbose
        self._issue_stats: Dict[str, int] = {}

    def analyze(
        self,
        queries: Union[str, List[str]],
        return_dataframe: bool = True
    ) -> Union[pd.DataFrame, List[DetectedIssue]]:
        """
        Analyze SQL queries for issues.

        Args:
            queries: Single query string or list of queries
            return_dataframe: Return pandas DataFrame (default True) or list of issues

        Returns:
            DataFrame with columns [issue, query, description, fix, impact, severity, line_number, count]
            or List[DetectedIssue] if return_dataframe=False
        """
        if self.verbose:
            print("Analyzing SQL queries...")

        # Normalize input
        if isinstance(queries, str):
            queries = [queries]

        metrics = AnalysisMetrics()
        start = time.time()

        issues: List[DetectedIssue] = self.detector.analyze(queries)

        # Update metrics counts
        metrics.total_queries = len(queries)
        metrics.total_issues = len(issues)
        for issue in issues:
            sev = issue.severity.value
            if sev == "critical":
                metrics.critical_issues += 1
            elif sev == "high":
                metrics.high_issues += 1
            elif sev == "medium":
                metrics.medium_issues += 1
            elif sev == "low":
                metrics.low_issues += 1

        metrics.total_time = time.time() - start

        if self.verbose and issues:
            unique_types: int = len(set(i.issue_type for i in issues))
            print(f"Found {len(issues)} issue(s) across {unique_types} categories")

        # Update internal stats
        self._update_stats(issues)

        # Return both issues and metrics
        return (self._to_dataframe(issues) if return_dataframe else issues, metrics)


    def analyze_parallel(
        self,
        queries: Union[str, List[str]],
        return_dataframe: bool = True,
        workers: Optional[int] = None
    ) -> Union[pd.DataFrame, List[DetectedIssue]]:
        """
        Analyze queries in parallel across multiple cores.

        Args:
            queries: Single query string or list of queries
            return_dataframe: Return pandas DataFrame (default True) or list of issues
            workers: Number of worker processes (None = auto)

        Returns:
            DataFrame or list of DetectedIssue objects
        """
        if isinstance(queries, str):
            queries = [queries]

        with ProcessPoolExecutor(max_workers=workers) as executor:
            results: List[List[DetectedIssue]] = list(executor.map(self.detector.analyze, queries))

        issues: List[DetectedIssue] = [issue for batch in results for issue in batch]

        self._update_stats(issues)

        return self._to_dataframe(issues) if return_dataframe else issues

    def _to_dataframe(self, issues: List[DetectedIssue]) -> pd.DataFrame:
        """
        Convert issues to DataFrame format.

        Args:
            issues: List of DetectedIssue objects

        Returns:
            pandas DataFrame with normalized issue data
        """
        if not issues:
            return pd.DataFrame(columns=[
                "issue", "query", "description", "fix", "impact", "severity", "line_number", "count"
            ])

        data: List[Dict[str, Any]] = []
        issue_groups: Dict[Tuple[str, str, str], Dict[str, Any]] = {}

        for issue in issues:
            key: Tuple[str, str, str] = (issue.issue_type, issue.fix, issue.impact)
            if key not in issue_groups:
                issue_groups[key] = {
                    "issue": issue.issue_type,
                    "queries": [],
                    "description": issue.description,
                    "fix": issue.fix,
                    "impact": issue.impact,
                    "severity": issue.severity.value,
                    "line_number": issue.line_number
                }
            issue_groups[key]["queries"].append(issue.query)

        for group in issue_groups.values():
            example_query: str = group["queries"][0]
            if len(example_query) > 60:
                example_query = example_query[:57] + "..."

            data.append({
                "issue": group["issue"],
                "query": example_query,
                "description": group["description"],
                "fix": group["fix"],
                "impact": group["impact"],
                "severity": group["severity"],
                "line_number": group["line_number"],
                "count": len(group["queries"])
            })

        return pd.DataFrame(data)

    def _update_stats(self, issues: List[DetectedIssue]) -> None:
        """
        Update internal issue statistics.

        Args:
            issues: List of DetectedIssue objects
        """
        for issue in issues:
            self._issue_stats[issue.issue_type] = self._issue_stats.get(issue.issue_type, 0) + 1

    def get_summary_stats(self) -> Dict[str, Any]:
        """
        Get summary statistics of analyzed issues.

        Returns:
            Dictionary with totals, breakdown, and timestamp
        """
        total_issues: int = sum(self._issue_stats.values())
        return {
            "total_issues_detected": total_issues,
            "unique_issue_types": len(self._issue_stats),
            "most_common_issue": max(self._issue_stats.items(), key=lambda x: x[1])[0] if self._issue_stats else None,
            "issue_breakdown": dict(self._issue_stats),
            "analysis_timestamp": datetime.now().isoformat()
        }

    def print_report(self, results: pd.DataFrame, detailed: bool = True) -> None:
        """
        Print formatted report of analysis results.

        Args:
            results: DataFrame of issues
            detailed: Whether to include detailed findings
        """
        if results.empty:
            print("✅ No SQL issues detected!")
            return

        print("\n" + "=" * 80)
        print("SQL ANALYSIS REPORT")
        print("=" * 80)

        total_issues: int = results["count"].sum()
        unique_types: int = len(results["issue"].unique())
        critical_count: int = len(results[results["severity"] == "critical"])
        high_count: int = len(results[results["severity"] == "high"])

        print("\n📊 SUMMARY:")
        print(f"   Total Issues: {total_issues}")
        print(f"   Issue Types: {unique_types}")
        if critical_count > 0:
            print(f"   🚨 Critical: {critical_count}")
        if high_count > 0:
            print(f"   ⚠️  High: {high_count}")

        if detailed:
            print("\n📋 DETAILED FINDINGS:")
            print("-" * 80)
            for severity in ["critical", "high", "medium", "low"]:
                severity_issues = results[results["severity"] == severity]
                if not severity_issues.empty:
                    severity_label: str = {
                        "critical": "🚨 CRITICAL",
                        "high": "⚠️  HIGH",
                        "medium": "⚡ MEDIUM",
                        "low": "ℹ️  LOW"
                    }[severity]
                    print(f"\n{severity_label} SEVERITY:")
                    for _, issue in severity_issues.iterrows():
                        print(f"\n   Issue: {issue['issue']}")
                        print(f"   Query: {issue['query']}")
                        print(f"   Fix: {issue['fix']}")
                        print(f"   Impact: {issue['impact']}")
                        if issue["count"] > 1:
                            print(f"   Occurrences: {issue['count']}")

        print("\n" + "=" * 80)

    def export_report(self, results: pd.DataFrame, format: str = "json", filename: Optional[str] = None) -> str:
        """
        Export analysis results to file.

        Args:
            results: DataFrame of issues
            format: Export format ("json", "csv", "html")
            filename: Optional output filename

        Returns:
            Path to exported file
        """
        if filename is None:
            timestamp: str = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"sql_analysis_{timestamp}.{format}"

        if format == "json":
            results.to_json(filename, orient="records", indent=2)
        elif format == "csv":
            results.to_csv(filename, index=False)
        elif format == "html":
            results.to_html(filename, index=False)
        else:
            raise ValueError(f"Unsupported format: {format}")

        return filename

    def suggest_indexes(self, query: Union[str, pd.DataFrame]) -> list[str]:
        index_patterns: list[str] = []

        # Handle DataFrame input
        if isinstance(query, pd.DataFrame):
            if query.empty:
                return []
            query = str(query.iloc[0]["query"])  # now query is str

        # At this point, query is guaranteed to be str
        query_upper = query.upper()

        if "WHERE" not in query_upper:
            return [
                "-- No WHERE clause found.",
                "-- Consider adding filters to reduce result set size."
            ]

        if "UPPER(" in query_upper:
            index_patterns.append("-- Functional index suggestion:")
            index_patterns.append("CREATE INDEX idx_func_email ON users (UPPER(email))")

        if "JOIN" in query_upper:
            index_patterns.append("-- For JOIN operations:")
            index_patterns.append("CREATE INDEX idx_join ON table1(column1, column2)")
            index_patterns.append("CREATE INDEX idx_join2 ON table2(column3, column4)")

        if "ORDER BY" in query_upper:
            index_patterns.append("-- For ORDER BY clause:")
            index_patterns.append("CREATE INDEX idx_order ON table(column1, column2)")

        if "GROUP BY" in query_upper:
            index_patterns.append("-- For GROUP BY clause:")
            index_patterns.append("CREATE INDEX idx_group ON table(column1, column2)")

        return index_patterns



    def compare_queries(self, query1: str, query2: str) -> Dict[str, Any]:
        """
        Compare two queries and report improvement metrics.

        Args:
            query1: Original query string
            query2: Optimized query string

        Returns:
            Dictionary with counts, improvement percentage, and remaining issues
        """
        issues1: List[DetectedIssue] = self.detector.analyze(query1)
        issues2: List[DetectedIssue] = self.detector.analyze(query2)
        return {
            "original_issues": len(issues1),
            "optimized_issues": len(issues2),
            "issues_resolved": len(issues1) - len(issues2),
            "improvement_percentage": (
                (len(issues1) - len(issues2)) / len(issues1) * 100
            ) if issues1 else 0,
            "remaining_issues": [i.issue_type for i in issues2]
        }


def analyze_sql(queries: Union[str, List[str]], verbose: bool = True) -> pd.DataFrame:
    """
    Convenience function to analyze SQL queries.

    Args:
        queries: Single query string or list of queries
        verbose: Whether to print analysis progress

    Returns:
        pandas DataFrame of analysis results
    """
    analyzer: QueryAnalyzer = QueryAnalyzer(verbose=verbose)
    return analyzer.analyze(queries)
