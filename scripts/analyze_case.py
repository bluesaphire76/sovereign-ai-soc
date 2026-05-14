import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from case_ai_analysis import generate_case_ai_analysis


def main():
    parser = argparse.ArgumentParser(description="Generate LLM analysis for an investigation case.")
    parser.add_argument("case_id", type=int, help="Case ID to analyze")

    args = parser.parse_args()

    result = generate_case_ai_analysis(args.case_id)

    print(f"Created case AI analysis #{result.id} for case #{result.case_id}")
    print(f"Model: {result.model}")
    print(f"Recommended status: {result.recommended_status}")
    print(f"Recommended severity: {result.recommended_severity}")
    print()
    print(result.analysis)


if __name__ == "__main__":
    main()
