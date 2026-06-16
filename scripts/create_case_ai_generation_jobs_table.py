import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from database import engine
from models import Base


def main():
    Base.metadata.create_all(bind=engine)
    print("case_ai_generation_jobs table ensured.")


if __name__ == "__main__":
    main()
