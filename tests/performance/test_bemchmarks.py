# tests/performance/test_benchmarks.py
import pytest
import subprocess
import sys
from slowql.core.analyzer import QueryAnalyzer

CLI_CMD = [sys.executable, "-m", "slowql.cli"]

# -------------------------------
# Analyzer Benchmarks
# -------------------------------

@pytest.mark.benchmark(group="analyzer")
def test_analyzer_fast_benchmark(benchmark, sample_queries):
    analyzer = QueryAnalyzer(verbose=False)
    queries = list(sample_queries.values())

    def run_analysis():
        df = analyzer.analyze(queries, return_dataframe=True)
        # Assert inside the benchmarked function
        assert not df.empty

    benchmark(run_analysis)


@pytest.mark.benchmark(group="analyzer")
def test_analyzer_parallel_benchmark(benchmark, sample_queries):
    analyzer = QueryAnalyzer(verbose=False)
    queries = list(sample_queries.values()) * 50  # scale up for parallel benefit

    def run_parallel():
        df = analyzer.analyze_parallel(queries, return_dataframe=True)
        assert not df.empty

    benchmark(run_parallel)

# -------------------------------
# CLI Benchmarks
# -------------------------------

@pytest.mark.benchmark(group="cli")
def test_cli_fast_mode_benchmark(benchmark, sample_sql_file):
    def run_cli():
        result = subprocess.run(
            CLI_CMD + ["--fast", "--no-intro", "--input-file", str(sample_sql_file)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "SLOWQL Analysis" in result.stdout

    benchmark(run_cli)


@pytest.mark.benchmark(group="cli")
def test_cli_parallel_mode_benchmark(benchmark, sample_sql_file):
    def run_cli_parallel():
        result = subprocess.run(
            CLI_CMD + ["--fast", "--no-intro", "--parallel", "--input-file", str(sample_sql_file)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "SLOWQL Analysis" in result.stdout

    benchmark(run_cli_parallel)
