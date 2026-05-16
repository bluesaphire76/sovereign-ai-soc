from pathlib import Path
import sys

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR))

from database import engine
from models import Base


def main():
    Base.metadata.create_all(bind=engine)
    print("Security audit table ensured.")


if __name__ == "__main__":
    main()
