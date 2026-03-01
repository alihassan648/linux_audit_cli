import os
import stat
import tempfile
from audit_pkg.scanner import FileScanner


def test_scanner_basic_scan():
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create test file
        file_path = os.path.join(temp_dir, "test.txt")

        with open(file_path, "w") as f:
            f.write("security test")

        # Make world writable
        os.chmod(file_path, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)

        scanner = FileScanner(temp_dir)
        results = scanner.scan()

        assert results["total_files"] == 1
        assert len(results["world_writable"]) == 1