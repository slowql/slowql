from slowql.parser.base import BaseParser


class TestBaseParserCoverage:
    def test_supports_dialect(self):
        class ConcreteParser(BaseParser):
            supported_dialects = ("postgres", "mysql")

            # abstract methods must be implemented to instantiate
            def parse(self, _sql, *, _dialect=None, _file_path=None):
                return []

            def parse_single(self, _sql, *, _dialect=None, _file_path=None):
                return None

            def detect_dialect(self, _sql):
                return None

            def normalize(self, _sql, *, _dialect=None):
                return ""

            def extract_tables(self, _sql, *, _dialect=None):
                return []

            def extract_columns(self, _sql, *, _dialect=None):
                return []

            def get_query_type(self, _sql):
                return None

        parser = ConcreteParser()
        assert parser.supports_dialect("postgres")
        assert parser.supports_dialect("POSTGRES")
        assert parser.supports_dialect("mysql")
        assert not parser.supports_dialect("sqlite")

    def test_supports_dialect_universal(self):
        class UniversalParserMock(BaseParser):
            supported_dialects = ()  # Empty means universal

            def parse(self, _sql, *, _dialect=None, _file_path=None):
                return []

            def parse_single(self, _sql, *, _dialect=None, _file_path=None):
                return None

            def detect_dialect(self, _sql):
                return None

            def normalize(self, _sql, *, _dialect=None):
                return ""

            def extract_tables(self, _sql, *, _dialect=None):
                return []

            def extract_columns(self, _sql, *, _dialect=None):
                return []

            def get_query_type(self, _sql):
                return None

        parser = UniversalParserMock()
        assert parser.supports_dialect("anything")
