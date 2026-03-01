import stat


class PermissionChecker:
    """
    Contains static methods for security risk detection.
    Pure logic. No IO. Easily testable.
    """

    @staticmethod
    def is_world_writable(mode: int) -> bool:
        return bool(mode & stat.S_IWOTH)

    @staticmethod
    def is_group_writable_root_owned(mode: int, uid: int) -> bool:
        return uid == 0 and bool(mode & stat.S_IWGRP)

    @staticmethod
    def is_suid(mode: int) -> bool:
        return bool(mode & stat.S_ISUID)

    @staticmethod
    def is_sgid(mode: int) -> bool:
        return bool(mode & stat.S_ISGID)

    @staticmethod
    def is_executable_non_root(mode: int, uid: int) -> bool:
        is_exec = bool(mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
        return is_exec and uid != 0