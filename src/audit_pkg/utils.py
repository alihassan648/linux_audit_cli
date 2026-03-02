import os

SYSTEM_DIRS = ["/etc", "/bin", "/usr", "/var"]


def is_system_directory(path: str) -> bool:
    return any(os.path.abspath(path).startswith(d) for d in SYSTEM_DIRS)


def risk_value(level: str) -> int:
    mapping = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4
    }
    return mapping.get(level.upper(), 1)


def calculate_risk_score(results):
    """
    Centralized risk scoring logic.
    Used by report generator and CLI engine.
    """

    return (
        len(results["world_writable"]) * 2 +
        len(results["suid_files"]) * 3 +
        len(results["sgid_files"]) * 3 +
        len(results["executable_non_root"]) * 2
    )


def determine_risk_level(score: int) -> str:
    """
    Convert numeric score into risk category.
    """

    if score >= 10:
        return "CRITICAL"
    elif score >= 6:
        return "HIGH"
    elif score >= 3:
        return "MEDIUM"

    return "LOW"