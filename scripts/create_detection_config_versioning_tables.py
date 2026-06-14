from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from database import engine
from models import DetectionConfigVersion

DetectionConfigVersion.__table__.create(bind=engine, checkfirst=True)

print("Detection config versioning table ready.")
