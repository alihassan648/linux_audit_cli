import stat


class PermissionChecker:

    @staticmethod
    def permission_string(mode: int) -> str:
        return stat.filemode(mode)

    @staticmethod
    def is_world_writable(mode: int) -> bool:
        return bool(mode & stat.S_IWOTH)

    @staticmethod
    def is_suid(mode: int) -> bool:
        return bool(mode & stat.S_ISUID)

    @staticmethod
    def is_sgid(mode: int) -> bool:
        return bool(mode & stat.S_ISGID)

    @staticmethod
    def is_executable(mode: int) -> bool:
        return bool(mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))

    @staticmethod
    def is_executable_non_root(mode: int, uid: int) -> bool:
        return PermissionChecker.is_executable(mode) and uid != 0

    @staticmethod
    def is_group_writable(mode: int) -> bool:
        return bool(mode & stat.S_IWGRP)