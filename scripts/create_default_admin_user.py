from pathlib import Path
import argparse
import os
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from auth_utils import hash_password
from database import SessionLocal
from models import AppUser


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--username", default=os.environ.get("AI_SOC_ADMIN_USERNAME", "admin"))
    parser.add_argument("--password", default=os.environ.get("AI_SOC_ADMIN_PASSWORD", "ChangeMe123!"))
    parser.add_argument("--display-name", default=os.environ.get("AI_SOC_ADMIN_DISPLAY_NAME", "SOC Administrator"))
    args = parser.parse_args()

    username = args.username.strip().lower()

    db = SessionLocal()

    try:
        existing = db.query(AppUser).filter(AppUser.username == username).first()

        if existing:
            print(f"Admin user already exists: {username}")
            return

        user = AppUser(
            username=username,
            display_name=args.display_name,
            role="ADMIN",
            password_hash=hash_password(args.password),
            is_active=True,
        )

        db.add(user)
        db.commit()

        print("Admin user created.")
        print(f"Username: {username}")
        print("Password: set from argument/env/default")
    finally:
        db.close()


if __name__ == "__main__":
    main()
