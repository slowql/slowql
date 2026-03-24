import tempfile
from pathlib import Path

from slowql.core.config import AnalysisConfig, Config
from slowql.core.engine import SlowQL


def _tmp_sql(content: str) -> Path:
    with tempfile.NamedTemporaryFile(suffix=".sql", mode="w", delete=False, encoding="utf-8") as f:
        f.write(content)
        return Path(f.name)

def test_analyze_files_parallel_vs_sequential():
    files = []
    for i in range(5):
        # A query that should raise no critical errors but maybe low/info
        files.append(_tmp_sql(f"SELECT id FROM users WHERE id = {i};"))

    try:
        # Sequential
        config_seq = Config(analysis=AnalysisConfig(parallel=False))
        engine_seq = SlowQL(config=config_seq)
        res_seq = engine_seq.analyze_files(files)

        # Parallel
        config_par = Config(analysis=AnalysisConfig(parallel=True, max_workers=2))
        engine_par = SlowQL(config=config_par)
        res_par = engine_par.analyze_files(files)

        assert len(res_seq.queries) == 5
        assert len(res_par.queries) == 5
        assert res_seq.statistics.total_queries == 5
        assert res_par.statistics.total_queries == 5
        assert res_seq.statistics.total_issues == res_par.statistics.total_issues
    finally:
        for f in files:
            f.unlink()
