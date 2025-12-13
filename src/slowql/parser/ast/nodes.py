# slowql/src/slowql/parser/ast/nodes.py
"""
AST node definitions for SlowQL.

This module defines a high-level AST representation that abstracts
over different SQL dialects. The nodes wrap sqlglot's AST to provide
a simpler, more consistent interface for analyzers.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING, Any, Callable, Iterator, TypeVar

if TYPE_CHECKING:
    from sqlglot import exp


T = TypeVar("T", bound="ASTNode")


class NodeType(Enum):
    """Types of AST nodes."""

    # Statements
    SELECT = auto()
    INSERT = auto()
    UPDATE = auto()
    DELETE = auto()
    MERGE = auto()
    CREATE = auto()
    ALTER = auto()
    DROP = auto()
    TRUNCATE = auto()

    # Expressions
    COLUMN = auto()
    LITERAL = auto()
    FUNCTION = auto()
    BINARY_OP = auto()
    UNARY_OP = auto()
    SUBQUERY = auto()
    CASE = auto()
    CAST = auto()

    # Clauses
    WHERE = auto()
    JOIN = auto()
    GROUP_BY = auto()
    ORDER_BY = auto()
    HAVING = auto()
    LIMIT = auto()
    OFFSET = auto()
    WINDOW = auto()

    # Table references
    TABLE = auto()
    ALIAS = auto()
    CTE = auto()

    # Other
    STAR = auto()
    WILDCARD = auto()
    CONDITION = auto()
    PARAMETER = auto()
    COMMENT = auto()
    UNKNOWN = auto()


class JoinType(Enum):
    """Types of SQL joins."""

    INNER = "INNER"
    LEFT = "LEFT"
    RIGHT = "RIGHT"
    FULL = "FULL"
    CROSS = "CROSS"
    NATURAL = "NATURAL"
    LATERAL = "LATERAL"


class Operator(Enum):
    """SQL operators."""

    # Comparison
    EQ = "="
    NE = "!="
    LT = "<"
    LE = "<="
    GT = ">"
    GE = ">="
    LIKE = "LIKE"
    ILIKE = "ILIKE"
    IN = "IN"
    NOT_IN = "NOT IN"
    BETWEEN = "BETWEEN"
    IS = "IS"
    IS_NOT = "IS NOT"

    # Logical
    AND = "AND"
    OR = "OR"
    NOT = "NOT"

    # Arithmetic
    ADD = "+"
    SUB = "-"
    MUL = "*"
    DIV = "/"
    MOD = "%"

    # Other
    CONCAT = "||"
    CAST = "::"


@dataclass
class ASTNode(ABC):
    """
    Base class for all AST nodes.

    All AST nodes inherit from this class and provide
    a consistent interface for traversal and inspection.
    """

    _raw: Any = field(default=None, repr=False)
    """Reference to the underlying sqlglot node."""

    @property
    @abstractmethod
    def node_type(self) -> NodeType:
        """Get the type of this node."""
        ...

    @property
    def children(self) -> list[ASTNode]:
        """Get child nodes."""
        return []

    @property
    def sql(self) -> str:
        """Get SQL representation of this node."""
        if self._raw is not None:
            return str(self._raw)
        return ""

    def walk(self) -> Iterator[ASTNode]:
        """
        Iterate over this node and all descendants.

        Yields:
            This node and all child nodes recursively.
        """
        yield self
        for child in self.children:
            yield from child.walk()

    def find_all(self, node_type: type[T]) -> Iterator[T]:
        """
        Find all nodes of a specific type.

        Args:
            node_type: The type of nodes to find.

        Yields:
            All matching nodes.
        """
        for node in self.walk():
            if isinstance(node, node_type):
                yield node

    def find_first(self, node_type: type[T]) -> T | None:
        """
        Find the first node of a specific type.

        Args:
            node_type: The type of node to find.

        Returns:
            The first matching node, or None.
        """
        for node in self.find_all(node_type):
            return node
        return None


class ASTVisitor(ABC):
    """
    Base class for AST visitors.

    Implement specific visit methods for nodes you want to handle.
    The default implementation visits all children.

    Example:
        >>> class ColumnCollector(ASTVisitor):
        ...     def __init__(self):
        ...         self.columns = []
        ...
        ...     def visit_column(self, node: Column) -> None:
        ...         self.columns.append(node.name)
        ...         self.generic_visit(node)
    """

    def visit(self, node: ASTNode) -> Any:
        """
        Visit a node by dispatching to the appropriate method.

        Args:
            node: The node to visit.

        Returns:
            Result of the visit method.
        """
        method_name = f"visit_{node.node_type.name.lower()}"
        visitor = getattr(self, method_name, self.generic_visit)
        return visitor(node)

    def generic_visit(self, node: ASTNode) -> None:
        """
        Default visitor that visits all children.

        Args:
            node: The node being visited.
        """
        for child in node.children:
            self.visit(child)


# =============================================================================
# Expression Nodes
# =============================================================================


@dataclass
class Expression(ASTNode):
    """Base class for expression nodes."""

    @property
    def node_type(self) -> NodeType:
        return NodeType.UNKNOWN


@dataclass
class Literal(Expression):
    """
    A literal value (string, number, boolean, null).

    Attributes:
        value: The Python value of the literal.
        literal_type: Type of literal (string, number, etc.).
    """

    value: Any = None
    literal_type: str = "unknown"

    @property
    def node_type(self) -> NodeType:
        return NodeType.LITERAL

    @property
    def is_string(self) -> bool:
        """Check if this is a string literal."""
        return self.literal_type == "string"

    @property
    def is_number(self) -> bool:
        """Check if this is a numeric literal."""
        return self.literal_type in ("int", "float", "number")

    @property
    def is_null(self) -> bool:
        """Check if this is NULL."""
        return self.literal_type == "null" or self.value is None


@dataclass
class Column(Expression):
    """
    A column reference.

    Attributes:
        name: Column name.
        table: Optional table name/alias.
        schema: Optional schema name.
    """

    name: str = ""
    table: str | None = None
    schema: str | None = None

    @property
    def node_type(self) -> NodeType:
        return NodeType.COLUMN

    @property
    def full_name(self) -> str:
        """Get fully qualified column name."""
        parts = []
        if self.schema:
            parts.append(self.schema)
        if self.table:
            parts.append(self.table)
        parts.append(self.name)
        return ".".join(parts)

    @property
    def is_star(self) -> bool:
        """Check if this is a wildcard (*)."""
        return self.name == "*"


@dataclass
class Function(Expression):
    """
    A function call.

    Attributes:
        name: Function name.
        args: List of argument expressions.
        distinct: Whether DISTINCT is applied (for aggregates).
        schema: Optional schema name.
    """

    name: str = ""
    args: list[Expression] = field(default_factory=list)
    distinct: bool = False
    schema: str | None = None

    @property
    def node_type(self) -> NodeType:
        return NodeType.FUNCTION

    @property
    def children(self) -> list[ASTNode]:
        return list(self.args)

    @property
    def is_aggregate(self) -> bool:
        """Check if this is an aggregate function."""
        aggregates = {
            "COUNT", "SUM", "AVG", "MIN", "MAX",
            "ARRAY_AGG", "STRING_AGG", "GROUP_CONCAT", "LISTAGG",
            "STDDEV", "VARIANCE", "VAR_POP", "VAR_SAMP",
            "PERCENTILE_CONT", "PERCENTILE_DISC",
        }
        return self.name.upper() in aggregates

    @property
    def is_window(self) -> bool:
        """Check if this is a window function."""
        windows = {
            "ROW_NUMBER", "RANK", "DENSE_RANK", "NTILE",
            "LAG", "LEAD", "FIRST_VALUE", "LAST_VALUE", "NTH_VALUE",
        }
        return self.name.upper() in windows


@dataclass
class BinaryOp(Expression):
    """
    A binary operation (left op right).

    Attributes:
        left: Left operand.
        operator: The operator.
        right: Right operand.
    """

    left: Expression | None = None
    operator: Operator | str = ""
    right: Expression | None = None

    @property
    def node_type(self) -> NodeType:
        return NodeType.BINARY_OP

    @property
    def children(self) -> list[ASTNode]:
        result: list[ASTNode] = []
        if self.left:
            result.append(self.left)
        if self.right:
            result.append(self.right)
        return result


@dataclass
class UnaryOp(Expression):
    """
    A unary operation (op operand).

    Attributes:
        operator: The operator.
        operand: The operand.
    """

    operator: Operator | str = ""
    operand: Expression | None = None

    @property
    def node_type(self) -> NodeType:
        return NodeType.UNARY_OP

    @property
    def children(self) -> list[ASTNode]:
        if self.operand:
            return [self.operand]
        return []


@dataclass
class Subquery(Expression):
    """
    A subquery expression.

    Attributes:
        query: The subquery.
        alias: Optional alias for the subquery.
    """

    query: Query | None = None
    alias: str | None = None

    @property
    def node_type(self) -> NodeType:
        return NodeType.SUBQUERY

    @property
    def children(self) -> list[ASTNode]:
        if self.query:
            return [self.query]
        return []


# =============================================================================
# Clause Nodes
# =============================================================================


@dataclass
class Condition(ASTNode):
    """
    A WHERE/HAVING condition.

    Wraps the condition expression with additional metadata.
    """

    expression: Expression | None = None

    @property
    def node_type(self) -> NodeType:
        return NodeType.CONDITION

    @property
    def children(self) -> list[ASTNode]:
        if self.expression:
            return [self.expression]
        return []


@dataclass
class Where(ASTNode):
    """
    A WHERE clause.

    Attributes:
        condition: The condition expression.
    """

    condition: Condition | None = None

    @property
    def node_type(self) -> NodeType:
        return NodeType.WHERE

    @property
    def children(self) -> list[ASTNode]:
        if self.condition:
            return [self.condition]
        return []

    @property
    def is_empty(self) -> bool:
        """Check if the WHERE clause is empty/missing."""
        return self.condition is None


@dataclass
class Join(ASTNode):
    """
    A JOIN clause.

    Attributes:
        table: The table being joined.
        join_type: Type of join (INNER, LEFT, etc.).
        condition: Join condition (ON clause).
        using: USING columns (alternative to ON).
    """

    table: Table | None = None
    join_type: JoinType = JoinType.INNER
    condition: Condition | None = None
    using: list[str] = field(default_factory=list)

    @property
    def node_type(self) -> NodeType:
        return NodeType.JOIN

    @property
    def children(self) -> list[ASTNode]:
        result: list[ASTNode] = []
        if self.table:
            result.append(self.table)
        if self.condition:
            result.append(self.condition)
        return result

    @property
    def has_condition(self) -> bool:
        """Check if join has a condition."""
        return self.condition is not None or len(self.using) > 0


@dataclass
class OrderBy(ASTNode):
    """
    An ORDER BY clause item.

    Attributes:
        expression: The expression to order by.
        ascending: True for ASC, False for DESC.
        nulls_first: Null ordering preference.
    """

    expression: Expression | None = None
    ascending: bool = True
    nulls_first: bool | None = None

    @property
    def node_type(self) -> NodeType:
        return NodeType.ORDER_BY

    @property
    def children(self) -> list[ASTNode]:
        if self.expression:
            return [self.expression]
        return []


# =============================================================================
# Table Nodes
# =============================================================================


@dataclass
class Table(ASTNode):
    """
    A table reference.

    Attributes:
        name: Table name.
        alias: Optional table alias.
        schema: Optional schema name.
        catalog: Optional catalog/database name.
    """

    name: str = ""
    alias: str | None = None
    schema: str | None = None
    catalog: str | None = None

    @property
    def node_type(self) -> NodeType:
        return NodeType.TABLE

    @property
    def full_name(self) -> str:
        """Get fully qualified table name."""
        parts = []
        if self.catalog:
            parts.append(self.catalog)
        if self.schema:
            parts.append(self.schema)
        parts.append(self.name)
        return ".".join(parts)

    @property
    def reference_name(self) -> str:
        """Get the name to use when referencing this table (alias or name)."""
        return self.alias or self.name


# =============================================================================
# Query Nodes
# =============================================================================


@dataclass
class Select(ASTNode):
    """
    A SELECT statement.

    Attributes:
        columns: Selected columns/expressions.
        from_clause: Tables in FROM clause.
        where: WHERE clause.
        joins: JOIN clauses.
        group_by: GROUP BY expressions.
        having: HAVING clause.
        order_by: ORDER BY items.
        limit: LIMIT value.
        offset: OFFSET value.
        distinct: Whether DISTINCT is applied.
        ctes: Common Table Expressions (WITH clause).
    """

    columns: list[Expression] = field(default_factory=list)
    from_clause: list[Table] = field(default_factory=list)
    where: Where | None = None
    joins: list[Join] = field(default_factory=list)
    group_by: list[Expression] = field(default_factory=list)
    having: Condition | None = None
    order_by: list[OrderBy] = field(default_factory=list)
    limit: int | None = None
    offset: int | None = None
    distinct: bool = False
    ctes: list[Subquery] = field(default_factory=list)

    @property
    def node_type(self) -> NodeType:
        return NodeType.SELECT

    @property
    def children(self) -> list[ASTNode]:
        result: list[ASTNode] = []
        result.extend(self.columns)
        result.extend(self.from_clause)
        if self.where:
            result.append(self.where)
        result.extend(self.joins)
        result.extend(self.group_by)
        if self.having:
            result.append(self.having)
        result.extend(self.order_by)
        result.extend(self.ctes)
        return result

    @property
    def has_where(self) -> bool:
        """Check if query has a WHERE clause."""
        return self.where is not None and not self.where.is_empty

    @property
    def has_aggregation(self) -> bool:
        """Check if query has aggregation."""
        return len(self.group_by) > 0 or any(
            isinstance(c, Function) and c.is_aggregate
            for c in self.columns
        )

    @property
    def selects_star(self) -> bool:
        """Check if query uses SELECT *."""
        for col in self.columns:
            if isinstance(col, Column) and col.is_star:
                return True
        return False

    @property
    def table_count(self) -> int:
        """Get number of tables (FROM + JOINs)."""
        return len(self.from_clause) + len(self.joins)


@dataclass
class Query(ASTNode):
    """
    A complete SQL query (may be SELECT, INSERT, UPDATE, DELETE, etc.).

    This is the top-level node returned by the parser.
    """

    statement: ASTNode | None = None
    query_type: NodeType = NodeType.UNKNOWN

    @property
    def node_type(self) -> NodeType:
        return self.query_type

    @property
    def children(self) -> list[ASTNode]:
        if self.statement:
            return [self.statement]
        return []

    @property
    def is_select(self) -> bool:
        return self.query_type == NodeType.SELECT

    @property
    def is_insert(self) -> bool:
        return self.query_type == NodeType.INSERT

    @property
    def is_update(self) -> bool:
        return self.query_type == NodeType.UPDATE

    @property
    def is_delete(self) -> bool:
        return self.query_type == NodeType.DELETE

    @property
    def is_ddl(self) -> bool:
        """Check if this is a DDL statement (CREATE, ALTER, DROP)."""
        return self.query_type in (
            NodeType.CREATE,
            NodeType.ALTER,
            NodeType.DROP,
            NodeType.TRUNCATE,
        )

    @property
    def is_dml(self) -> bool:
        """Check if this is a DML statement (SELECT, INSERT, UPDATE, DELETE)."""
        return self.query_type in (
            NodeType.SELECT,
            NodeType.INSERT,
            NodeType.UPDATE,
            NodeType.DELETE,
            NodeType.MERGE,
        )