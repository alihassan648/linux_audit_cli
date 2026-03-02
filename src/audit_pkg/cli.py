import argparse
import sys

from audit_pkg.scanner import FileScanner


def determine_risk_level(score: int) -> str:
    if score >= 10:
        return "CRITICAL"
    elif score >= 6:
        return "HIGH"
    elif score >= 3:
        return "MEDIUM"
    else:
        return "LOW"


def risk_value(level: str) -> int:
    mapping = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4
    }
    return mapping.get(level.upper(), 1)


def main():
    parser = argparse.ArgumentParser(description="Linux Security Audit CLI")
    parser.add_argument("scan", help="Scan command")
    parser.add_argument("--path", required=True, help="Directory path to scan")
    parser.add_argument("--min-risk", default="LOW", help="Minimum risk filter")

    args = parser.parse_args()

    scanner = FileScanner(args.path)
    results = scanner.scan()
    total_files = results["total_files"]
    findings = results["findings"]
    risk_score = results["risk_score"]
    overall_risk = determine_risk_level(risk_score)

    # Filter findings
    min_risk_val = risk_value(args.min_risk)
    filtered = []

    for item in findings:
        item_level = determine_risk_level(len(item["risks"]))
        if risk_value(item_level) >= min_risk_val:
            filtered.append(item)

    print("\nScan Summary")
    print("------------")
    print(f"Total Files Scanned: {total_files}")
    print(f"Total Findings: {len(filtered)}")

    print("\nOverall Risk Assessment")
    print("-----------------------")
    print(f"Risk Score: {risk_score}")
    print(f"Risk Level: {overall_risk}")

    print("\nDetailed Findings")
    print("-----------------")

    for item in filtered:
        print(f"\nPath: {item['path']}")
        print(f"Permissions: {item['permissions']}")
        print(f"Owner: {item['owner']}")
        print(f"Risks: {', '.join(item['risks'])}")

    # Exit codes for CI
    if overall_risk == "CRITICAL":
        sys.exit(3)
    elif overall_risk == "HIGH":
        sys.exit(2)
    elif overall_risk == "MEDIUM":
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()