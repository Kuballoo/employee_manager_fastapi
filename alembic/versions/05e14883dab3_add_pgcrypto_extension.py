"""add pgcrypto extension

Revision ID: 05e14883dab3
Revises: 
Create Date: 2026-02-03 14:46:13.499275

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '05e14883dab3'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade():
    op.execute('CREATE EXTENSION IF NOT EXISTS pgcrypto')

def downgrade():
    op.execute('DROP EXTENSION IF EXISTS pgcrypto')

