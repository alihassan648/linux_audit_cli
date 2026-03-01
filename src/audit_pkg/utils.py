import json
from datetime import datetime


# -----------------------------
# Risk Scoring Functions
# -----------------------------

def calculate_risk_score(results):
    score = 0

    score += len(results["suid_files"]) * 5
    score += len(results["world_writable"]) * 3
    score += len(results["sgid_files"]) * 3
    score += len(results["executable_non_root"]) * 1

    return score


def determine_risk_level(score):
    if score == 0:
        return "LOW"
    elif 1 <= score <= 4:
        return "MEDIUM"
    elif 5 <= score <= 9:
        return "HIGH"
    else:
        return "CRITICAL"


# -----------------------------
# JSON Export Functions
# -----------------------------

def export_json_report(path, results):
    score = calculate_risk_score(results)
    level = determine_risk_level(score)

    output = {
        "scan_timestamp": datetime.utcnow().isoformat(),
        "scanned_path": path,
        "summary": {
            "total_files": results["total_files"],
            "world_writable": results["world_writable"],
            "suid_files": results["suid_files"],
            "sgid_files": results["sgid_files"],
            "executable_non_root": results["executable_non_root"],
            "errors": results["errors"],
        },
        "risk_assessment": {
            "risk_score": score,
            "risk_level": level
        }
    }

    return output


def write_json_to_file(filename, data):
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)