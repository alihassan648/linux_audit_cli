import os
import pwd
from audit_pkg.permissions import PermissionChecker

SYSTEM_DIRS = ["/etc", "/bin", "/usr", "/var"]


class FileScanner:
    def __init__(self, path: str):
        self.path = path

    def is_system_directory(self, path: str) -> bool:
        return any(os.path.abspath(path).startswith(d) for d in SYSTEM_DIRS)

    def scan(self):
        total_files = 0
        risk_score = 0

        # Old expected categories (for tests)
        world_writable = []
        suid_files = []
        sgid_files = []
        executable_non_root = []

        # New detailed findings
        findings = []

        for root, _, files in os.walk(self.path):
            for name in files:
                file_path = os.path.join(root, name)

                try:
                    stat_info = os.stat(file_path)
                    total_files += 1

                    mode = stat_info.st_mode
                    uid = stat_info.st_uid
                    owner = pwd.getpwuid(uid).pw_name

                    file_risks = []

                    if PermissionChecker.is_world_writable(mode):
                        world_writable.append(file_path)
                        file_risks.append("WORLD_WRITABLE")
                        risk_score += 2

                    if PermissionChecker.is_suid(mode):
                        suid_files.append(file_path)
                        file_risks.append("SUID")
                        risk_score += 3

                    if PermissionChecker.is_sgid(mode):
                        sgid_files.append(file_path)
                        file_risks.append("SGID")
                        risk_score += 3

                    if PermissionChecker.is_executable_non_root(mode, uid):
                        executable_non_root.append(file_path)
                        file_risks.append("EXECUTABLE_NON_ROOT")
                        risk_score += 2

                    if self.is_system_directory(file_path) and uid != 0:
                        file_risks.append("NON_ROOT_OWNED_SYSTEM_FILE")
                        risk_score += 4

                    if uid == 0 and PermissionChecker.is_group_writable(mode):
                        file_risks.append("ROOT_GROUP_WRITABLE")
                        risk_score += 3

                    if file_risks:
                        findings.append({
                            "path": file_path,
                            "permissions": PermissionChecker.permission_string(mode),
                            "owner": owner,
                            "risks": file_risks
                        })

                except Exception:
                    continue

        return {
            "total_files": total_files,
            "world_writable": world_writable,
            "suid_files": suid_files,
            "sgid_files": sgid_files,
            "executable_non_root": executable_non_root,
            "findings": findings,
            "risk_score": risk_score
        }