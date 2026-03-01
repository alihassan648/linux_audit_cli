import os
import stat
from audit_pkg.permissions import PermissionChecker


def test_world_writable_detection():
    mode = stat.S_IWOTH
    assert PermissionChecker.is_world_writable(mode) is True


def test_world_writable_negative():
    mode = stat.S_IRUSR
    assert PermissionChecker.is_world_writable(mode) is False


def test_suid_detection():
    mode = stat.S_ISUID
    assert PermissionChecker.is_suid(mode) is True


def test_executable_non_root():
    mode = stat.S_IXUSR
    uid = 1000
    assert PermissionChecker.is_executable_non_root(mode, uid) is True