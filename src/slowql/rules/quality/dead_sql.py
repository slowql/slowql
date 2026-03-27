import re
from typing import Any

from sqlglot import exp

from slowql.core.models import AnalysisResult, Category, Dimension, Issue, Query, Severity
from slowql.rules.base import ASTRule, Rule

# Defensive imports for Block and EndStatement which might be missing in some sqlglot versions/environments
_Block = getattr(exp, "Block", None)
_EndStatement = getattr(exp, "EndStatement", None)


class UnusedObjectRule(Rule):
    """
    Detects unused database objects (views, procedures, functions).
    """

    id = "QUAL-DEAD-001"
    name = "Unused Database Object"
    dimension = Dimension.QUALITY
    severity = Severity.MEDIUM
    category = Category.QUAL_TECH_DEBT

    def __init__(self) -> None:
        super().__init__()
        self.definitions: dict[str, dict[str, Any]] = {}
        self.usages: set[str] = set()

    def check(self, query: Query) -> list[Issue]:
        if not query.ast:
            return []

        definition = self._extract_definition_info(query)
        created_name = None
        if definition:
            obj_type, name = definition
            created_name = name
            self.definitions[name] = {
                "type": obj_type,
                "query": query,
            }

        ast = query.ast
        for node in ast.walk():
            name = getattr(node, "name", "").upper()
            if name and name != created_name:
                self.usages.add(name)

            if isinstance(node, exp.Identifier):
                name = node.this.upper()
                if name != created_name:
                    self.usages.add(name)

        return []

    def _extract_definition_info(self, query: Query) -> tuple[str, str] | None:
        ast = query.ast
        if _Block and isinstance(ast, _Block):
            ast = ast.find(exp.Create)

        if not isinstance(ast, exp.Create):
            ast = query.ast.find(exp.Create)

        if not isinstance(ast, exp.Create):
            return None

        obj = ast.this
        identifier = obj.find(exp.Identifier)
        if not identifier:
            return None

        name = identifier.this.upper()
        raw_upper = query.raw.upper()

        if " VIEW " in raw_upper:
            return "VIEW", name
        if " PROCEDURE " in raw_upper or " PROC " in raw_upper:
            return "PROCEDURE", name
        if " FUNCTION " in raw_upper:
            return "FUNCTION", name

        return "TABLE", name

    def check_project(self, result: AnalysisResult) -> list[Issue]:
        issues = []
        for name, def_info in self.definitions.items():
            query = def_info["query"]
            if name in ("SELECT", "FROM", "WHERE", "AND", "OR", "IN", "NULL", "AS", "CREATE",
                       "VIEW", "PROCEDURE", "FUNCTION", "INT", "INTEGER", "BEGIN", "END",
                       "RETURN", "RETURNS", "PROCEDURE_NAME", "TABLE_NAME"):
                continue

            if name not in self.usages:
                issues.append(self.create_issue(
                    query=query,
                    message=f"Database object '{name}' is defined but never used in the analyzed project.",
                    snippet=query.raw,
                ))

        self.definitions = {}
        self.usages = set()
        return issues


class DuplicateQueryRule(Rule):
    """
    Detects duplicate or near-duplicate queries.
    """

    id = "QUAL-DEAD-003"
    name = "Duplicate Query"
    severity = Severity.LOW
    dimension = Dimension.QUALITY
    category = Category.QUAL_TECH_DEBT

    def check(self, query: Query) -> list[Issue]:
        return []

    def _get_fingerprint(self, query: Query) -> str:
        if not query.ast:
             return query.normalized
        ast_copy = query.ast.copy()
        for literal in ast_copy.find_all(exp.Literal):
            literal.replace(exp.Placeholder())
        return ast_copy.sql()

    def check_project(self, result: AnalysisResult) -> list[Issue]:
        seen: dict[str, list[Query]] = {}
        for query in result.queries:
            if "CREATE " in query.raw.upper() or "ALTER " in query.raw.upper() or "DROP " in query.raw.upper():
                continue
            fingerprint = self._get_fingerprint(query)
            if fingerprint not in seen:
                seen[fingerprint] = []
            seen[fingerprint].append(query)

        issues = []
        for fingerprint, queries in seen.items():
            if len(queries) > 1:
                for i in range(1, len(queries)):
                    issues.append(self.create_issue(
                        query=queries[i],
                        message=f"Duplicate query detected. Same normalized logic found {len(queries)} times in project.",
                        snippet=queries[i].raw,
                    ))
        return issues


class UnreachableCodeRule(ASTRule):
    """
    Detects code that is unreachable after a RETURN statement.
    """

    id = "QUAL-DEAD-002"
    name = "Unreachable Code"
    severity = Severity.MEDIUM
    dimension = Dimension.QUALITY
    category = Category.QUAL_TECH_DEBT

    def check_ast(self, query: Query, ast: exp.Expression) -> list[Issue]:
        """Check AST for unreachable code after RETURN, independent of parent pointers."""
        issues: list[Issue] = []
        reported_ids: set[int] = set()

        # Walk all nodes to find any that might have list arguments (sibling containers)
        for node in ast.walk():
            if not hasattr(node, "args"):
                continue

            for arg_val in node.args.values():
                if not isinstance(arg_val, list) or not arg_val:
                    continue

                # We found a potential sibling container (like Block.expressions)
                return_found = False
                for stmt in arg_val:
                    if stmt is None:
                        continue

                    if return_found:
                        # This node is after a return in the same block/container
                        if self._should_skip_node(stmt):
                            continue
                        if id(stmt) in reported_ids:
                            continue

                        reported_ids.add(id(stmt))
                        snippet = str(stmt).strip()
                        issues.append(
                            self.create_issue(
                                query=query,
                                message=f"Unreachable code detected: '{snippet}'",
                                snippet=snippet,
                            )
                        )
                    elif self._is_return_basic(stmt):
                        return_found = True

        # Fallback: raw text analysis for procedure bodies where
        # sqlglot splits BEGIN...END into separate top-level statements
        if not issues:
            issues.extend(self._check_procedure_body_raw(query))

        return issues

    def _should_skip_node(self, node: exp.Expression) -> bool:
        """Check if this node should be skipped for unreachable reporting."""
        if _EndStatement and isinstance(node, _EndStatement):
            return True
        if isinstance(node, exp.Semicolon):
            return True
        # Also skip structural markers
        sql = str(node).upper().strip().rstrip(';')
        return sql in ("", "END", "GO", ";")

    def _is_return_basic(self, stmt: exp.Expression) -> bool:
        """Core logic for identifying a return node with multiple strategies."""
        # 1. Standard Return node
        if isinstance(stmt, exp.Return):
            return True

        # 2. String representation check (very robust for T-SQL artifacts)
        try:
            sql = str(stmt).upper().strip().rstrip(';')
            if sql == "RETURN" or sql.startswith("RETURN "):
                return True
        except Exception:
            pass

        # 3. Name attributes or Identifier name
        return getattr(stmt, "name", "").upper() == "RETURN"

    def _check_procedure_body_raw(self, query: Query) -> list[Issue]:
        """Detect unreachable code via raw SQL when sqlglot splits procedure bodies."""
        raw = query.raw
        if not raw:
            return []

        raw_upper = raw.upper()

        if not any(kw in raw_upper for kw in ("PROCEDURE", "FUNCTION", "PROC ")):
            return []

        begin_match = re.search(r'\bBEGIN\b', raw_upper)
        if not begin_match:
            return []

        end_matches = list(re.finditer(r'\bEND\b', raw_upper))
        if not end_matches:
            return []

        body = raw[begin_match.end():end_matches[-1].start()]
        stmts = [s.strip() for s in body.split(';') if s.strip()]

        issues: list[Issue] = []
        return_seen = False
        for stmt_text in stmts:
            normalized = stmt_text.upper().strip()
            if return_seen:
                if normalized in ("", "END", "GO"):
                    continue
                issues.append(
                    self.create_issue(
                        query=query,
                        message=f"Unreachable code detected: '{stmt_text}'",
                        snippet=stmt_text,
                    )
                )
            elif normalized == "RETURN" or normalized.startswith("RETURN "):
                return_seen = True

        return issues
