import ast
from pathlib import Path
from typing import Any

from slowql.migrations.base import MigrationFile, MigrationProvider


class AlembicSQLScanner(ast.NodeVisitor):
    """
    Scans Alembic migration AST for 'op' calls and converts them to SQL strings.
    """
    def __init__(self) -> None:
        self.statements: list[str] = []

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            if node.func.value.id == "op":
                stmt = self._convert_op_call(node)
                if stmt:
                    self.statements.append(stmt)
        self.generic_visit(node)

    def _convert_op_call(self, node: ast.Call) -> str | None:  # noqa: PLR0911
        func_name = node.func.attr if hasattr(node.func, "attr") else ""
        args = node.args

        if func_name == "create_table":
            table_name = self._get_val(args[0])
            columns = []
            for arg in args[1:]:
                # Check for op.Column or Column
                if isinstance(arg, ast.Call):
                     c_name = self._get_column_name(arg)
                     if c_name:
                         columns.append(f"{c_name} INT")

            cols_str = ", ".join(columns) or "dummy_id INT"
            return f"CREATE TABLE {table_name} ({cols_str});"

        elif func_name == "add_column":
            table_name = self._get_val(args[0])
            col_node = args[1]
            # Handle op.column or op.Column
            if isinstance(col_node, ast.Call):
                func_attr = getattr(col_node.func, "attr", "").lower()
                if func_attr == "column" and len(col_node.args) > 0:
                    col_name = self._get_val(col_node.args[0])
                    return f"ALTER TABLE {table_name} ADD COLUMN {col_name} INT;"

            # Fallback if first arg is the name
            col_name = self._get_val(col_node)
            return f"ALTER TABLE {table_name} ADD COLUMN {col_name} INT;"

        elif func_name == "drop_column":
            table_name = self._get_val(args[0])
            col_name = self._get_val(args[1])
            return f"ALTER TABLE {table_name} DROP COLUMN {col_name};"

        elif func_name == "drop_table":
            table_name = self._get_val(args[0])
            return f"DROP TABLE {table_name};"

        elif func_name == "create_index":
            idx_name = self._get_val(args[0])
            table_name = self._get_val(args[1])
            cols_node = args[2]
            cols = [self._get_val(c) for c in cols_node.elts] if isinstance(cols_node, ast.List) else []
            cols_str = ", ".join(cols) or "dummy"
            return f"CREATE INDEX {idx_name} ON {table_name} ({cols_str});"

        return None

    def _get_column_name(self, node: ast.Call) -> str | None:
        """Extracts column name from op.Column call."""
        func_attr = getattr(node.func, "attr", "").lower()
        if func_attr == "column" and len(node.args) > 0:
            return self._get_val(node.args[0])
        return None

    def _get_val(self, node: ast.AST) -> Any:
        if isinstance(node, ast.Constant):
            return node.value
        return str(node)

class AlembicProvider(MigrationProvider):
    def detect(self, path: Path) -> bool:
        # Check if it's a directory containing alembic files
        if path.is_dir():
            return (
                (path / "alembic.ini").exists() or
                (path / "versions").is_dir() or
                (path / "migrations" / "versions").is_dir()
            )
        return False

    def get_migrations(self, path: Path) -> list[MigrationFile]:  # noqa: PLR0912
        versions_dir = path / "versions"
        if not versions_dir.is_dir():
            versions_dir = path / "migrations" / "versions"

        if not versions_dir.is_dir():
            # Try path as versions dir
            versions_dir = path
            if not any(versions_dir.glob("*.py")):
                return []

        migrations = []
        for file in versions_dir.glob("*.py"):
            if file.name == "__init__.py":
                continue

            try:
                tree = ast.parse(file.read_text())

                # Extract revision and down_revision
                revision = None
                down_revision = None
                for node in tree.body:
                    if isinstance(node, ast.Assign):
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                if target.id == "revision" and isinstance(node.value, ast.Constant):
                                    revision = node.value.value
                                elif target.id == "down_revision" and isinstance(node.value, ast.Constant):
                                    down_revision = node.value.value

                if not revision:
                    continue

                # Scan for op calls in upgrade()
                scanner = AlembicSQLScanner()
                for node in tree.body:
                    if isinstance(node, ast.FunctionDef) and node.name == "upgrade":
                        scanner.visit(node)

                sql_content = "\n".join(scanner.statements)

                migrations.append(MigrationFile(
                    version=str(revision),
                    path=file,
                    content=sql_content,
                    depends_on=[str(down_revision)] if down_revision else (),
                    metadata={"framework": "alembic"}
                ))
            except Exception:
                continue

        # Sort migrations by version string (handles 001, 002 etc.)
        return sorted(migrations, key=lambda m: m.version)
