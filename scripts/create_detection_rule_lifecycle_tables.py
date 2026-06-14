import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from database import engine
from models import DetectionRuleLifecycleEvent, DetectionRuleLifecycleItem


def main():
    print("Creating detection rule lifecycle tables...")
    DetectionRuleLifecycleItem.__table__.create(bind=engine, checkfirst=True)
    DetectionRuleLifecycleEvent.__table__.create(bind=engine, checkfirst=True)
    print("Done.")


if __name__ == "__main__":
    main()
