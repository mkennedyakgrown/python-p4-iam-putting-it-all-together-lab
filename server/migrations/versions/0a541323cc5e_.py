"""empty message

Revision ID: 0a541323cc5e
Revises: 3b3744d64ac0
Create Date: 2024-04-18 16:25:49.116834

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0a541323cc5e'
down_revision = '3b3744d64ac0'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('recipes', schema=None) as batch_op: batch_op.create_check_constraint('check_1', 'LENGTH(instructions) >= 50')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('recipes', schema=None) as batch_op: batch_op.drop_constraint('my_check_constraint', 'my_table')

    # ### end Alembic commands ###
