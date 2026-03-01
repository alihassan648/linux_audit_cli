from audit_pkg.utils import calculate_risk_score, determine_risk_level


def generate_summary_report(results):
    score = calculate_risk_score(results)
    level = determine_risk_level(score)

    report = []
    report.append("\nScan Summary")
    report.append("------------")
    report.append(f"Total Files Scanned: {results['total_files']}")

    report.append("\nRisks Found:")
    report.append(f"World Writable Files: {len(results['world_writable'])}")
    report.append(f"SUID Files: {len(results['suid_files'])}")
    report.append(f"SGID Files: {len(results['sgid_files'])}")
    report.append(f"Executable Non-Root Files: {len(results['executable_non_root'])}")

    report.append("\nOverall Risk Assessment")
    report.append("-----------------------")
    report.append(f"Risk Score: {score}")
    report.append(f"Risk Level: {level}")

    return "\n".join(report)