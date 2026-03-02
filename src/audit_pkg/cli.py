import argparse
import sys

from audit_pkg.scanner import FileScanner
from audit_pkg.report import generate_summary_report, generate_json_report
from audit_pkg.utils import determine_risk_level, calculate_risk_score


def main():
    parser = argparse.ArgumentParser(description="Linux Security Audit CLI")

    parser.add_argument("scan")
    parser.add_argument("--path", required=True)

    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text"
    )

    parser.add_argument("--output", help="JSON report output file")
    parser.add_argument("--min-risk", default="LOW")

    args = parser.parse_args()

    scanner = FileScanner(args.path)
    results = scanner.scan()

    # Text Report
    print(generate_summary_report(results))

    # JSON Report
    if args.format == "json":
        if not args.output:
            print("Output file required for JSON report")
            sys.exit(1)

        generate_json_report(
            args.path,
            results,
            args.output
        )

    risk_score = calculate_risk_score(results)
    risk_level = determine_risk_level(risk_score)

    # Exit code logic
    if risk_level == "CRITICAL":
        sys.exit(3)
    elif risk_level == "HIGH":
        sys.exit(2)
    elif risk_level == "MEDIUM":
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()