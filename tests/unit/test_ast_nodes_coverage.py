
from slowql.parser.ast.nodes import (
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


def test_literal_node():
    lit = Literal(value="test", literal_type="string")
    assert lit.node_type == NodeType.LITERAL
    assert lit.is_string is True
    assert lit.is_number is False
    assert lit.is_null is False

    lit_num = Literal(value=42, literal_type="int")
    assert lit_num.is_number is True
    assert lit_num.is_string is False

    lit_null = Literal(value=None, literal_type="null")
    assert lit_null.is_null is True

def test_column_node():
    col = Column(name="id", table="users", schema="public")
    assert col.node_type == NodeType.COLUMN
    assert col.full_name == "public.users.id"
    assert col.is_star is False

    star = Column(name="*")
    assert star.is_star is True
    assert star.full_name == "*"

def test_function_node():
    f = Function(name="COUNT", args=[Column(name="id")])
    assert f.node_type == NodeType.FUNCTION
    assert f.is_aggregate is True
    assert f.is_window is False
    assert len(f.children) == 1

    w = Function(name="ROW_NUMBER")
    assert w.is_window is True
    assert w.is_aggregate is False

def test_binary_op_node():
    b = BinaryOp(left=Column(name="a"), operator=Operator.EQ, right=Literal(value=1))
    assert b.node_type == NodeType.BINARY_OP
    assert len(b.children) == 2

def test_unary_op_node():
    u = UnaryOp(operator=Operator.NOT, operand=Column(name="a"))
    assert u.node_type == NodeType.UNARY_OP
    assert len(u.children) == 1

    u_empty = UnaryOp(operator=Operator.NOT)
    assert len(u_empty.children) == 0

def test_subquery_node():
    q = Query(query_type=NodeType.SELECT)
    s = Subquery(query=q, alias="t")
    assert s.node_type == NodeType.SUBQUERY
    assert len(s.children) == 1

    s_empty = Subquery()
    assert len(s_empty.children) == 0

def test_condition_and_where():
    c = Condition(expression=Column(name="a"))
    assert c.node_type == NodeType.CONDITION
    assert len(c.children) == 1

    c_empty = Condition()
    assert len(c_empty.children) == 0

    w = Where(condition=c)
    assert w.node_type == NodeType.WHERE
    assert len(w.children) == 1
    assert w.is_empty is False

    # A completely empty where node
    w_empty = Where(condition=None)
    assert len(w_empty.children) == 0
    assert w_empty.is_empty is True

def test_join_node():
    t = Table(name="users")
    c = Condition(expression=Column(name="a"))
    j = Join(table=t, join_type=JoinType.LEFT, condition=c)
    assert j.node_type == NodeType.JOIN
    assert len(j.children) == 2
    assert j.has_condition is True

    j_empty = Join()
    assert len(j_empty.children) == 0
    assert j_empty.has_condition is False

def test_order_by_node():
    o = OrderBy(expression=Column(name="a"), ascending=False)
    assert o.node_type == NodeType.ORDER_BY
    assert len(o.children) == 1

    o_empty = OrderBy()
    assert len(o_empty.children) == 0

def test_table_node():
    t = Table(name="users", alias="u", schema="public", catalog="db")
    assert t.node_type == NodeType.TABLE
    assert t.full_name == "db.public.users"
    assert t.reference_name == "u"

    t2 = Table(name="orders")
    assert t2.full_name == "orders"
    assert t2.reference_name == "orders"

def test_select_node():
    s = Select()
    s.columns = [Column(name="id"), Function(name="COUNT")]
    s.from_clause = [Table(name="users")]
    s.where = Where(condition=Condition())
    s.joins = [Join(table=Table(name="orders"))]
    s.group_by = [Column(name="id")]
    s.having = Condition()
    s.order_by = [OrderBy()]
    s.ctes = [Subquery()]

    assert s.node_type == NodeType.SELECT
    # 2 cols + 1 from + 1 where + 1 join + 1 group + 1 having + 1 order + 1 cte = 9
    assert len(s.children) == 9
    assert s.has_where is True
    assert s.has_aggregation is True
    assert s.selects_star is False
    assert s.table_count == 2

    s.columns.append(Column(name="*"))
    assert s.selects_star is True

def test_query_node():
    q = Query(query_type=NodeType.SELECT, statement=Select())
    assert q.is_select is True
    assert q.is_insert is False
    assert q.is_update is False
    assert q.is_delete is False
    assert q.is_dml is True
    assert q.is_ddl is False
    assert len(q.children) == 1

    q_empty = Query()
    assert len(q_empty.children) == 0

    q_insert = Query(query_type=NodeType.INSERT)
    assert q_insert.is_insert is True

    q_update = Query(query_type=NodeType.UPDATE)
    assert q_update.is_update is True

    q_delete = Query(query_type=NodeType.DELETE)
    assert q_delete.is_delete is True

    q_drop = Query(query_type=NodeType.DROP)
    assert q_drop.is_ddl is True
    assert q_drop.is_dml is False

def test_ast_visitor():
    from slowql.parser.ast.nodes import ASTVisitor

    class TestVisitor(ASTVisitor):
        def __init__(self):
            self.visited = []

        def visit_table(self, node):
            self.visited.append(node.name)

    v = TestVisitor()
    t = Table(name="visited_table")
    v.visit(t)
    assert "visited_table" in v.visited

    # Generic visit fallback
    c = Column(name="id")
    v.visit(c) # Should not crash, just falls back
