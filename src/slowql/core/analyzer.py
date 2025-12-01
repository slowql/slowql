from typing import List, Dict, Any, Union, Optional
import pandas as pd
from datetime import datetime
from concurrent.futures import ProcessPoolExecutor
from .detector import QueryDetector, DetectedIssue


class QueryAnalyzer:
    """
    SQL Query Analyzer

    Coordinates the analysis of SQL queries for performance issues,
    anti-patterns, and potential bugs. Provides both raw results
    and formatted output.
    """

    def __init__(self, verbose: bool = True):
        self.detector = QueryDetector()
        self.verbose = verbose
        self._issue_stats = {}

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

        # Run detector
        issues: List[DetectedIssue] = self.detector.analyze(queries)

        if self.verbose and issues:
            unique_types = len(set(i.issue_type for i in issues))
            print(f"Found {len(issues)} issue(s) across {unique_types} categories")

        # Update internal stats
        self._update_stats(issues)

        # Return in requested format
        if return_dataframe:
            return self._to_dataframe(issues)
        else:
            return issues


    def analyze_parallel(
        self,
        queries: Union[str, List[str]],
        return_dataframe: bool = True,
        workers: int = None
    ) -> Union[pd.DataFrame, List[DetectedIssue]]:
        """Analyze queries in parallel across multiple cores."""
        if isinstance(queries, str):
            queries = [queries]

        with ProcessPoolExecutor(max_workers=workers) as executor:
            results = list(executor.map(self.detector.analyze, queries))

        issues = [issue for batch in results for issue in batch]

        self._update_stats(issues)

        if return_dataframe:
            return self._to_dataframe(issues)
        return issues

    def _to_dataframe(self, issues: List[DetectedIssue]) -> pd.DataFrame:
        """Convert issues to DataFrame format."""
        if not issues:
            return pd.DataFrame(columns=[
                "issue", "query", "description", "fix", "impact", "severity", "line_number", "count"
            ])

        data = []
        issue_groups: Dict[tuple, Dict[str, Any]] = {}

        for issue in issues:
            key = (issue.issue_type, issue.fix, issue.impact)
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
            example_query = group["queries"][0]
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
        for issue in issues:
            self._issue_stats[issue.issue_type] = self._issue_stats.get(issue.issue_type, 0) + 1

    def get_summary_stats(self) -> Dict[str, Any]:
        total_issues = sum(self._issue_stats.values())
        return {
            "total_issues_detected": total_issues,
            "unique_issue_types": len(self._issue_stats),
            "most_common_issue": max(self._issue_stats.items(), key=lambda x: x[1])[0] if self._issue_stats else None,
            "issue_breakdown": dict(self._issue_stats),
            "analysis_timestamp": datetime.now().isoformat()
        }

    def print_report(self, results: pd.DataFrame, detailed: bool = True) -> None:
        if results.empty:
            print("✅ No SQL issues detected!")
            return

        print("\n" + "=" * 80)
        print("SQL ANALYSIS REPORT")
        print("=" * 80)

        total_issues = results["count"].sum()
        unique_types = len(results["issue"].unique())
        critical_count = len(results[results["severity"] == "critical"])
        high_count = len(results[results["severity"] == "high"])

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
                    severity_label = {
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
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
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

    def suggest_indexes(self, results: pd.DataFrame) -> List[str]:
        index_suggestions = []
        if results.empty or "issue" not in results.columns:
            return index_suggestions

        index_patterns = {
            "Non-SARGable WHERE": "Consider functional index on computed column",
            "Function on Indexed Column": "CREATE INDEX idx_name ON table(LOWER(column))",
            "Leading Wildcard": "Consider full-text index",
            "OR Prevents Index": "Create separate indexes for each condition"
        }

        for issue_type in results["issue"].unique():
            if issue_type in index_patterns:
                index_suggestions.append(f"-- For {issue_type} issues:")
                index_suggestions.append(index_patterns[issue_type])

        return index_suggestions

    def compare_queries(self, query1: str, query2: str) -> Dict[str, Any]:
        issues1 = self.detector.analyze(query1)
        issues2 = self.detector.analyze(query2)
        return {
            "original_issues": len(issues1),
            "optimized_issues": len(issues2),
            "issues_resolved": len(issues1) - len(issues2),
            "improvement_percentage": ((len(issues1) - len(issues2)) / len(issues1) * 100) if issues1 else 0,
            "remaining_issues": [i.issue_type for i in issues2]
        }


def analyze_sql(queries: Union[str, List[str]], verbose: bool = True) -> pd.DataFrame:
    analyzer = QueryAnalyzer(verbose=verbose)
    return analyzer.analyze(queries)
