# Import all models so Alembic and SQLAlchemy can discover them via Base.metadata.
from app.models.cbom import CBOMDocument
from app.models.finding import Finding
from app.models.notification import Notification, NotificationPreference
from app.models.organisation import Organisation
from app.models.project import Group, Project
from app.models.sbom import SBOMDocument
from app.models.scan import Scan
from app.models.user import User

__all__ = [
    "CBOMDocument",
    "Finding",
    "Group",
    "Notification",
    "NotificationPreference",
    "Organisation",
    "Project",
    "SBOMDocument",
    "Scan",
    "User",
]
