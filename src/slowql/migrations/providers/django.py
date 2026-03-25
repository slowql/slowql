import ast
from pathlib import Path
from typing import Any

from slowql.migrations.base import MigrationFile, MigrationProvider


class DjangoSQLScanner(ast.NodeVisitor):
    """
    Scans Django migration AST for 'operations' and converts them to SQL strings.
    """
    def __init__(self) -> None:
        self.statements: list[str] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        if node.name == "Migration":
            for body_item in node.body:
                if isinstance(body_item, ast.Assign):
                    for target in body_item.targets:
                        if isinstance(target, ast.Name) and target.id == "operations":
                            self._handle_operations(body_item.value)
        self.generic_visit(node)

    def _handle_operations(self, node: ast.AST) -> None:
        if isinstance(node, ast.List):
            for op_node in node.elts:
                stmt = self._convert_django_op(op_node)
                if stmt:
                    self.statements.append(stmt)

    def _convert_django_op(self, node: ast.AST) -> str | None:
        if not isinstance(node, ast.Call):
            return None

        # Determine the operation type (CreateModel, AddField, etc.)
        func = node.func
        op_type = ""
        if isinstance(func, ast.Attribute):
            op_type = func.attr
        elif isinstance(func, ast.Name):
            op_type = func.id

        kwargs = {kw.arg: kw.value for kw in node.keywords}

        if op_type == "CreateModel":
            name = self._get_val(kwargs.get("name")).lower()
            return f"CREATE TABLE {name} (dummy_id INT);"

        elif op_type == "AddField":
            model_name = self._get_val(kwargs.get("model_name")).lower()
            name = self._get_val(kwargs.get("name"))
            return f"ALTER TABLE {model_name} ADD COLUMN {name} INT;"

        elif op_type == "RemoveField":
            model_name = self._get_val(kwargs.get("model_name")).lower()
            name = self._get_val(kwargs.get("name"))
            return f"ALTER TABLE {model_name} DROP COLUMN {name};"

        elif op_type == "DeleteModel":
            name = self._get_val(kwargs.get("name")).lower()
            return f"DROP TABLE {name};"

        elif op_type == "RunSQL":
            # Direct SQL
            if node.args:
                sql = self._get_val(node.args[0])
                if isinstance(sql, str):
                    return sql
            elif "sql" in kwargs:
                sql = self._get_val(kwargs["sql"])
                if isinstance(sql, str):
                    return sql

        return None

    def _get_val(self, node: ast.AST) -> Any:
        if isinstance(node, ast.Constant):
            return node.value
        return str(node)

class DjangoProvider(MigrationProvider):
    def detect(self, path: Path) -> bool:
        if path.is_dir():
            # Check for migrations folders
            return any(path.glob("**/migrations"))
        return False

    def get_migrations(self, path: Path) -> list[MigrationFile]:
        # Find all migrations folders
        migrations_folders = list(path.glob("**/migrations"))
        all_migrations = []

        for folder in migrations_folders:
            for file in folder.glob("*.py"):
                if file.name == "__init__.py":
                    continue

                try:
                    tree = ast.parse(file.read_text())
                    scanner = DjangoSQLScanner()
                    scanner.visit(tree)

                    sql_content = "\n".join(scanner.statements)

                    # Versioning: use the filename prefix (e.g., 0001)
                    version = file.stem.split("_")[0]

                    # Extract dependencies
                    dependencies = []
                    for node in ast.walk(tree):
                        if isinstance(node, ast.Assign):
                            for target in node.targets:
                                if isinstance(target, ast.Name) and target.id == "dependencies":
                                    if isinstance(node.value, ast.List):
                                        for dep in node.value.elts:
                                            # dep is usually a tuple ('app', '0001_initial')
                                            if isinstance(dep, ast.Tuple) and len(dep.elts) > 1:
                                                dep_val = dep.elts[1]
                                                dep_version_str = self._get_val(dep_val)
                                                if isinstance(dep_version_str, str):
                                                    dep_version = dep_version_str.split("_")[0]
                                                    dependencies.append(dep_version)

                    all_migrations.append(MigrationFile(
                        version=version,
                        path=file,
                        content=sql_content,
                        depends_on=tuple(dependencies),
                        metadata={"framework": "django", "app": folder.parent.name}
                    ))
                except Exception:
                    continue

        return sorted(all_migrations, key=lambda m: m.version)

    def _get_val(self, node: ast.AST) -> Any:
        if isinstance(node, ast.Constant):
            return node.value
        return str(node)
