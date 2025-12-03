import os

class Telemetry:
    """Anonymous usage telemetry (opt-in only)."""
    
    def __init__(self):
        # Enable telemetry only if env var is set
        self.enabled = os.getenv("SLOWQL_TELEMETRY", "false").lower() == "true"
    
    def track_analysis(self, metrics: dict):
        """Send anonymous metrics (no SQL content)."""
        if not self.enabled:
            return
        # Example: send metrics to a server or log them
        # Only detector counts, timings — never query text
        print("Telemetry:", metrics)
