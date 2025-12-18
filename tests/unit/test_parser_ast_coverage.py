from slowql.parser.ast.nodes import (
    ASTNode,
    ASTVisitor,
    BinaryOp,
    Column,
    Condition,
    Function,
    Join,
    JoinType,
    Literal,
    NodeType,
    Operator,
    OrderBy,
    Query,
    Select,
    Subquery,
    Table,
    UnaryOp,
    Where,
)


class TestASTNodes:
    def test_node_type_enum(self):
        assert NodeType.SELECT.name == "SELECT"
        assert NodeType.UNKNOWN.name == "UNKNOWN"

    def test_join_type_enum(self):
        assert JoinType.INNER.value == "INNER"
        assert JoinType.LEFT.value == "LEFT"

    def test_operator_enum(self):
        assert Operator.EQ.value == "="
        assert Operator.AND.value == "AND"

    def test_ast_node_base_methods(self):
        # Create a mock subclass since ASTNode is abstract
        class MockNode(ASTNode):
            @property
            def node_type(self):
                return NodeType.UNKNOWN

            @property
            def children(self):
                return []

        node = MockNode(_raw="raw_repr")
        assert node.sql == "raw_repr"

        node_no_raw = MockNode()
        assert node_no_raw.sql == ""

        # Test walk
        assert list(node.walk()) == [node]

        # Test find_all and find_first
        assert list(node.find_all(MockNode)) == [node]
        assert node.find_first(MockNode) == node
        assert node.find_first(Literal) is None

    def test_literal_node(self):
        l_str = Literal(value="test", literal_type="string")
        assert l_str.node_type == NodeType.LITERAL
        assert l_str.is_string
        assert not l_str.is_number
        assert not l_str.is_null
        assert l_str.children == []

        l_num = Literal(value=123, literal_type="int")
        assert l_num.is_number
        assert not l_num.is_string

        l_null = Literal(value=None, literal_type="null")
        assert l_null.is_null

        l_none = Literal(value=None)
        assert l_none.is_null

    def test_column_node(self):
        col = Column(name="col1", table="t1", schema="s1")
        assert col.node_type == NodeType.COLUMN
        assert col.full_name == "s1.t1.col1"
        assert not col.is_star
        assert col.children == []

        col_star = Column(name="*")
        assert col_star.is_star
        assert col_star.full_name == "*"

        col_simple = Column(name="col")
        assert col_simple.full_name == "col"

    def test_function_node(self):
        arg = Literal(value=1)
        func = Function(name="COUNT", args=[arg])
        assert func.node_type == NodeType.FUNCTION
        assert func.children == [arg]
        assert func.is_aggregate
        assert not func.is_window

        func_win = Function(name="ROW_NUMBER")
        assert not func_win.is_aggregate
        assert func_win.is_window

        func_normal = Function(name="LOWER")
        assert not func_normal.is_aggregate
        assert not func_normal.is_window

    def test_binary_op_node(self):
        left = Literal(value=1)
        right = Literal(value=2)
        op = BinaryOp(left=left, operator=Operator.ADD, right=right)
        assert op.node_type == NodeType.BINARY_OP
        assert op.children == [left, right]

        op_partial = BinaryOp(left=left)
        assert op_partial.children == [left]

        op_empty = BinaryOp()
        assert op_empty.children == []

    def test_unary_op_node(self):
        operand = Literal(value=True)
        op = UnaryOp(operator=Operator.NOT, operand=operand)
        assert op.node_type == NodeType.UNARY_OP
        assert op.children == [operand]

        op_empty = UnaryOp()
        assert op_empty.children == []

    def test_subquery_node(self):
        q = Query()
        sub = Subquery(query=q, alias="sub")
        assert sub.node_type == NodeType.SUBQUERY
        assert sub.children == [q]

        sub_empty = Subquery()
        assert sub_empty.children == []

    def test_condition_node(self):
        expr = Literal(value=True)
        cond = Condition(expression=expr)
        assert cond.node_type == NodeType.CONDITION
        assert cond.children == [expr]

        cond_empty = Condition()
        assert cond_empty.children == []

    def test_where_node(self):
        cond = Condition(expression=Literal(value=True))
        where = Where(condition=cond)
        assert where.node_type == NodeType.WHERE
        assert where.children == [cond]
        assert not where.is_empty

        where_empty = Where()
        assert where_empty.children == []
        assert where_empty.is_empty

    def test_join_node(self):
        table = Table(name="t1")
        join = Join(table=table)
        assert join.node_type == NodeType.JOIN
        assert join.children == [table]
        assert not join.has_condition

        cond = Condition(expression=Literal(value=True))
        join_cond = Join(table=table, condition=cond)
        assert join_cond.children == [table, cond]
        assert join_cond.has_condition

        join_using = Join(table=table, using=["id"])
        assert join_using.has_condition

    def test_order_by_node(self):
        expr = Column(name="col")
        order = OrderBy(expression=expr)
        assert order.node_type == NodeType.ORDER_BY
        assert order.children == [expr]

        order_empty = OrderBy()
        assert order_empty.children == []

    def test_table_node(self):
        table = Table(name="t1", alias="a1", schema="s1", catalog="c1")
        assert table.node_type == NodeType.TABLE
        assert table.children == []
        assert table.full_name == "c1.s1.t1"
        assert table.reference_name == "a1"

        table_simple = Table(name="t1")
        assert table_simple.full_name == "t1"
        assert table_simple.reference_name == "t1"

    def test_select_node(self):
        col = Column(name="col")
        tbl = Table(name="tbl")
        sel = Select(columns=[col], from_clause=[tbl])

        assert sel.node_type == NodeType.SELECT
        # Basic children check (columns + from)
        children = sel.children
        assert col in children
        assert tbl in children

        assert not sel.has_where
        assert not sel.has_aggregation
        assert not sel.selects_star
        assert sel.table_count == 1

        # Add where
        cond = Condition(expression=Literal(value=True))
        where = Where(condition=cond)
        sel.where = where
        assert sel.has_where
        assert where in sel.children

        # Add join
        join = Join(table=Table(name="t2"))
        sel.joins = [join]
        assert join in sel.children
        assert sel.table_count == 2

        # Add group by
        sel.group_by = [Column(name="col")]
        assert sel.has_aggregation
        assert sel.group_by[0] in sel.children

        # Add having
        sel.having = Condition(expression=Literal(value=True))
        assert sel.having in sel.children

        # Add order by
        sel.order_by = [OrderBy(expression=Column(name="col"))]
        assert sel.order_by[0] in sel.children

        # Add CTEs
        sel.ctes = [Subquery(query=Query())]
        assert sel.ctes[0] in sel.children

        # Select star
        sel_star = Select(columns=[Column(name="*")])
        assert sel_star.selects_star

        # Aggregation in columns
        sel_agg = Select(columns=[Function(name="COUNT")])
        assert sel_agg.has_aggregation

    def test_query_node(self):
        sel = Select()
        q = Query(statement=sel, query_type=NodeType.SELECT)
        assert q.node_type == NodeType.SELECT
        assert q.children == [sel]
        assert q.is_select
        assert q.is_dml
        assert not q.is_ddl
        assert not q.is_insert

        q_insert = Query(query_type=NodeType.INSERT)
        assert q_insert.is_insert
        assert q_insert.is_dml

        q_update = Query(query_type=NodeType.UPDATE)
        assert q_update.is_update

        q_delete = Query(query_type=NodeType.DELETE)
        assert q_delete.is_delete

        q_create = Query(query_type=NodeType.CREATE)
        assert q_create.is_ddl
        assert not q_create.is_dml

        q_alter = Query(query_type=NodeType.ALTER)
        assert q_alter.is_ddl

        q_drop = Query(query_type=NodeType.DROP)
        assert q_drop.is_ddl

        q_trunc = Query(query_type=NodeType.TRUNCATE)
        assert q_trunc.is_ddl

        q_empty = Query()
        assert q_empty.children == []

    def test_visitor(self):
        class TestVisitor(ASTVisitor):
            def __init__(self):
                self.visited = []

            def visit_column(self, node):
                self.visited.append("column")
                self.generic_visit(node)

            def visit_literal(self, _node):
                self.visited.append("literal")

        visitor = TestVisitor()
        col = Column(name="col")
        lit = Literal(value=1)

        # Should visit column then generic visit (children), but column has no children
        visitor.visit(col)
        assert visitor.visited == ["column"]

        # Should visit literal
        visitor.visited = []
        visitor.visit(lit)
        assert visitor.visited == ["literal"]

        # Generic visit on node with children
        op = BinaryOp(left=lit, right=col)
        visitor.visited = []
        visitor.visit(op)  # Should fallback to generic_visit
        # generic_visit visits child lit ("literal") then child col ("column")
        assert visitor.visited == ["literal", "column"]
