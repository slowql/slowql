
import pytest
from unittest.mock import MagicMock, patch
import sys
from slowql.analyzers.registry import AnalyzerRegistry, analyzer
from slowql.core.models import Dimension

class MockEp:
    def __init__(self, name, load_return, raise_error=None):
        self.name = name
        self._load_return = load_return
        self._raise_error = raise_error
        
    def load(self):
        if self._raise_error:
            raise self._raise_error
        return self._load_return

class TestAnalyzerRegistryCoverage:
    def test_discover_py39(self):
        # Mock sys.version_info to be 3.9
        with patch("sys.version_info", (3, 9)):
            with patch("importlib.metadata.entry_points") as mock_eps:
                # Python < 3.10 returns dict of lists
                mock_analyzer_cls = MagicMock()
                mock_analyzer_cls.name = "mock_ana"
                mock_inst = MagicMock()
                mock_inst.name = "mock_ana"
                mock_analyzer_cls.return_value = mock_inst
                
                ep = MockEp("mock_ana", mock_analyzer_cls)
                mock_eps.return_value = {"slowql.analyzers": [ep]}
                
                registry = AnalyzerRegistry()
                count = registry.discover()
                # Should find 1 mock analyzer + builtins (if they load). 
                # Builtins logic might run real imports. We should probably mock _load_builtin_analyzers to 0 to isolate.
                assert count >= 1

    def test_discover_exceptions_and_types(self):
        registry = AnalyzerRegistry()
        
        # Mock successful class load
        class MockAnalyzerClass:
            name = "valid_cls"
            dimension = Dimension.SECURITY
            priority = 1
            enabled = True
            rules = []
            def __init__(self):
                pass
                
        cls_ep = MockEp("valid_cls", MockAnalyzerClass)
        
        # Mock object load (not class)
        obj_inst = MagicMock()
        obj_inst.name = "valid_obj"
        obj_ep = MockEp("valid_obj", obj_inst)
        
        # Mock error load
        err_ep = MockEp("err", None, raise_error=Exception("Load failed"))
        
        eps = [cls_ep, obj_ep, err_ep]
        
        with patch("sys.version_info", (3, 10)):
             with patch("importlib.metadata.entry_points", return_value=eps):
                 with patch("sys.stderr.write"): # Suppress error prints
                     registry.discover()
                     
        assert "valid_cls" in registry._analyzers
        assert "valid_obj" in registry._analyzers

    def test_load_builtins_importerror(self):
        registry = AnalyzerRegistry()
        # Mock __import__ to raise ImportError
        with patch("builtins.__import__", side_effect=ImportError):
            count = registry._load_builtin_analyzers()
            assert count == 0

    def test_load_builtins_exception(self):
        registry = AnalyzerRegistry()
        with patch("builtins.__import__", side_effect=Exception("Crash")):
            with patch("sys.stderr.write"):
                count = registry._load_builtin_analyzers()
                assert count == 0

    def test_decorator_no_name(self):
        # Test @analyzer() without arguments (or just defaults)
        from slowql.analyzers.registry import get_registry
        reg = get_registry()
        
        # Cleanup before
        if "decorated" in reg:
             reg.unregister("decorated")

        @analyzer(priority=1)
        class DecoratedAnalyzer:
            name = "decorated"
            enabled = True
            dimension = Dimension.SECURITY
            rules = []
            # Add analyze method to prevent AttributeError in other tests
            def analyze(self, query, config=None):
                return []
            
        assert "decorated" in reg
        assert reg.get("decorated").priority == 1
        
        # Cleanup after
        reg.unregister("decorated")
