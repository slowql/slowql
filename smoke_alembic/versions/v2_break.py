revision = 'v2'
down_revision = 'v1'

def upgrade():
    op.drop_table('users')
