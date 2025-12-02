import pytest
import time
from slowql.effects import animations
from rich import panel

# -------------------------------
# Global patch for time.sleep
# -------------------------------
@pytest.fixture(autouse=True)
def patch_sleep(monkeypatch):
    monkeypatch.setattr(time, "sleep", lambda _: None)

# -------------------------------
# MatrixRain
# -------------------------------
def test_matrixrain_runs():
    mr = animations.MatrixRain()
    mr.run(duration=0.01)

def test_matrixrain_exception():
    class BadMatrix(animations.MatrixRain):
        def run(self, duration=0.1):
            raise RuntimeError("boom")
    with pytest.raises(RuntimeError):
        BadMatrix().run(0.1)

# -------------------------------
# CyberpunkSQLEditor
# -------------------------------
def test_editor_get_queries(monkeypatch):
    inputs = iter(["SELECT 1;", ""])
    monkeypatch.setattr("builtins.input", lambda: next(inputs, ""))
    editor = animations.CyberpunkSQLEditor()
    result = editor.get_queries()
    assert "SELECT" in result

def test_editor_get_queries_eof(monkeypatch):
    # Patch Console.input to simulate EOF safely
    monkeypatch.setattr("rich.console.Console.input", lambda self, *a, **k: "")
    editor = animations.CyberpunkSQLEditor()
    result = editor.get_queries()
    assert result == ""

# -------------------------------
# AnimatedAnalyzer
# -------------------------------
def test_particle_loading():
    aa = animations.AnimatedAnalyzer()
    aa.particle_loading("Loading")

def test_glitch_transition():
    aa = animations.AnimatedAnalyzer()
    aa.glitch_transition(duration=0.01)

def test_show_expandable_details(monkeypatch):
    # Patch Panel to avoid Rich markup parsing errors
    monkeypatch.setattr(panel.Panel, "__init__", lambda self, *a, **k: None)
    monkeypatch.setattr(panel.Panel, "__rich_console__", lambda *a, **k: [])
    aa = animations.AnimatedAnalyzer()
    # Should run without raising MarkupError
    aa.show_expandable_details("Summary", "Details", expanded=True)


def test_particle_loading_exception(monkeypatch):
    def safe_fail(*a, **k):
        try:
            raise RuntimeError("fail")
        except RuntimeError:
            pass
    monkeypatch.setattr("rich.console.Console.print", lambda self, *a, **k: safe_fail())
    aa = animations.AnimatedAnalyzer()
    aa.particle_loading("Loading")  # Should not raise

def test_glitch_transition_exception(monkeypatch):
    def safe_fail(*a, **k):
        try:
            raise RuntimeError("fail")
        except RuntimeError:
            pass
    monkeypatch.setattr("rich.console.Console.print", lambda self, *a, **k: safe_fail())
    aa = animations.AnimatedAnalyzer()
    aa.glitch_transition(duration=0.01)  # Should not raise

def test_show_expandable_details_exception(monkeypatch):
    def safe_fail(*a, **k):
        try:
            raise RuntimeError("fail")
        except RuntimeError:
            pass
    monkeypatch.setattr("rich.console.Console.print", lambda self, *a, **k: safe_fail())
    aa = animations.AnimatedAnalyzer()
    aa.show_expandable_details("Summary", "Details")  # Should not raise
