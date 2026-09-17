"""Production schema baseline including context-aware JIT access.

Revision ID: 20260917_01
Revises: None
"""

from alembic import op

from database import Base
import models.db_models  # noqa: F401


revision = "20260917_01"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # A baseline revision for a repository that previously used create_all.
    # Existing installations are stamped after schema verification; fresh
    # PostgreSQL deployments receive the complete metadata-managed schema.
    Base.metadata.create_all(bind=op.get_bind(), checkfirst=True)


def downgrade():
    # Deliberately non-destructive: production history and security audit data
    # must not be silently dropped by a downgrade.
    pass
