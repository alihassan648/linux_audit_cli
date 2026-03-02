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