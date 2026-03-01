import os
from typing import Dict, List
from audit_pkg.permissions import PermissionChecker
from audit_pkg.logger import get_logger

logger = get_logger()


class FileScanner:
    """
    Responsible for scanning directories and collecting security risks.
    """

    def __init__(self, root_path: str):
        self.root_path = root_path
        self.results = {
            "total_files": 0,
            "world_writable": [],
            "group_writable_root_owned": [],
            "suid_files": [],
            "sgid_files": [],
            "executable_non_root": [],
            "errors": []
        }

    def scan(self) -> Dict[str, List[str]]:
        for root, _, files in os.walk(self.root_path):
            for file in files:
                file_path = os.path.join(root, file)
                self._process_file(file_path)

        return self.results

    def _process_file(self, file_path: str):
        try:
            stat_info = os.stat(file_path, follow_symlinks=False)
            mode = stat_info.st_mode
            uid = stat_info.st_uid

            self.results["total_files"] += 1

            if PermissionChecker.is_world_writable(mode):
                self.results["world_writable"].append(file_path)

            if PermissionChecker.is_group_writable_root_owned(mode, uid):
                self.results["group_writable_root_owned"].append(file_path)

            if PermissionChecker.is_suid(mode):
                self.results["suid_files"].append(file_path)

            if PermissionChecker.is_sgid(mode):
                self.results["sgid_files"].append(file_path)

            if PermissionChecker.is_executable_non_root(mode, uid):
                self.results["executable_non_root"].append(file_path)

        except PermissionError as e:
            logger.warning(f"Permission denied: {file_path}")
            self.results["errors"].append(file_path)

        except Exception as e:
            logger.error(f"Unexpected error processing {file_path}: {e}")
            self.results["errors"].append(file_path)