from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from database import engine
from models import Base


def main():
    Base.metadata.create_all(bind=engine)
    print("case_closure_checklists table ensured.")


if __name__ == "__main__":
    main()
