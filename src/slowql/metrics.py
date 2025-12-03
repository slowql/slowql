import time
from dataclasses import dataclass, field
from typing import Dict, List

@dataclass
class AnalysisMetrics:
    total_queries: int = 0
    total_issues: int = 0
    critical_issues: int = 0
    high_issues: int = 0
    medium_issues: int = 0
    low_issues: int = 0
    
    detector_timings: Dict[str, float] = field(default_factory=dict)
    parse_time: float = 0.0
    total_time: float = 0.0
    
    def add_timing(self, detector_name: str, duration: float):
        """Record timing for a detector run."""
        self.detector_timings[detector_name] = duration
    
    def to_dict(self) -> dict:
        """Convert metrics to dictionary for reporting/export."""
        return {
            "summary": {
                "total_queries": self.total_queries,
                "total_issues": self.total_issues,
                "breakdown": {
                    "critical": self.critical_issues,
                    "high": self.high_issues,
                    "medium": self.medium_issues,
                    "low": self.low_issues,
                }
            },
            "performance": {
                "parse_time_ms": round(self.parse_time * 1000, 2),
                "total_time_ms": round(self.total_time * 1000, 2),
                "detector_timings_ms": {
                    k: round(v * 1000, 2) 
                    for k, v in self.detector_timings.items()
                }
            }
        }
