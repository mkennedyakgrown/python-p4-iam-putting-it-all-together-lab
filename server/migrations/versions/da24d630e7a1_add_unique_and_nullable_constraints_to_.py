"""Add unique and nullable constraints to User username

Revision ID: da24d630e7a1
Revises: 70113dd0f57b
Create Date: 2024-04-18 13:34:03.112853

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'da24d630e7a1'
down_revision = '70113dd0f57b'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.alter_column('username',
               existing_type=sa.VARCHAR(),
               nullable=False)
        batch_op.create_unique_constraint('unique', ['username'])

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_constraint('username', type_='unique')
        batch_op.alter_column('username',
               existing_type=sa.VARCHAR(),
               nullable=True)

    # ### end Alembic commands ###
