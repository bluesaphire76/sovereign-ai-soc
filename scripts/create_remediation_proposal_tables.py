import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from database import engine
from models import Base, RemediationProposal, RemediationProposalEvent


def main() -> None:
    Base.metadata.create_all(
        bind=engine,
        tables=[
            RemediationProposal.__table__,
            RemediationProposalEvent.__table__,
        ],
    )
    print("Remediation proposal tables are ready.")


if __name__ == "__main__":
    main()
