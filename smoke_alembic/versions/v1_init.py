revision = 'v1'
down_revision = None

def upgrade():
    op.create_table('users', op.column('id', op.Integer))
