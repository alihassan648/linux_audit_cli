import json
from datetime import datetime
from audit_pkg.utils import calculate_risk_score, determine_risk_level


def generate_summary_report(results):
    score = calculate_risk_score(results)
    level = determine_risk_level(score)

    report_lines = []

    report_lines.append("\nScan Summary")
    report_lines.append("------------")
    report_lines.append(f"Total Files Scanned: {results['total_files']}")

    report_lines.append("\nRisks Found:")
    report_lines.append(f"World Writable Files: {len(results['world_writable'])}")
    report_lines.append(f"SUID Files: {len(results['suid_files'])}")
    report_lines.append(f"SGID Files: {len(results['sgid_files'])}")
    report_lines.append(f"Executable Non-Root Files: {len(results['executable_non_root'])}")

    report_lines.append("\nOverall Risk Assessment")
    report_lines.append("-----------------------")
    report_lines.append(f"Risk Score: {score}")
    report_lines.append(f"Risk Level: {level}")

    return "\n".join(report_lines)


def generate_json_report(path, results, output_file):
    report = {
        "scan_timestamp": datetime.utcnow().isoformat(),
        "scanned_path": path,
        "summary": results,
        "risk_score": calculate_risk_score(results),
        "risk_level": determine_risk_level(
            calculate_risk_score(results)
        )
    }

    with open(output_file, "w") as f:
        json.dump(report, f, indent=4)