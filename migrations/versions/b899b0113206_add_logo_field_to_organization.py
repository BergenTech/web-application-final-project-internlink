"""Add logo field to Organization

Revision ID: b899b0113206
Revises: ca99e4bae36d
Create Date: 2024-06-18 08:22:21.906203

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b899b0113206'
down_revision = 'ca99e4bae36d'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('organization', schema=None) as batch_op:
        batch_op.add_column(sa.Column('logo', sa.String(length=100), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('organization', schema=None) as batch_op:
        batch_op.drop_column('logo')

    # ### end Alembic commands ###