# slowql/src/slowql/parser/ast/__init__.py
"""
AST (Abstract Syntax Tree) module for SlowQL.

This module provides:
- High-level AST node wrappers for cross-dialect compatibility
- AST traversal utilities
- Pattern matching on AST structures

The AST layer abstracts away dialect-specific differences, providing
a consistent interface for analyzers to work with.
"""

from __future__ import annotations

from slowql.parser.ast.nodes import (
    ASTNode,
    ASTVisitor,
    BinaryOp,
    Column,
    Condition,
    Expression,
    Function,
    Join,
    Literal,
    OrderBy,
    Query,
    Select,
    Subquery,
    Table,
    UnaryOp,
    Where,
)

__all__ = [
    "ASTNode",
    "ASTVisitor",
    "BinaryOp",
    "Column",
    "Condition",
    "Expression",
    "Function",
    "Join",
    "Literal",
    "OrderBy",
    "Query",
    "Select",
    "Subquery",
    "Table",
    "UnaryOp",
    "Where",
]
