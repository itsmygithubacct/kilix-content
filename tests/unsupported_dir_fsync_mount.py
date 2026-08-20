"""Mount a test-only passthrough FUSE filesystem with no directory fsync.

The backing tree keeps normal file durability.  Only ``fsyncdir`` returns
``EINVAL``, modeling a real mounted filesystem that cannot satisfy the receipt
store's directory-durability contract.  This helper requires fusepy 3.0.1 and
must run in the foreground; the acceptance controller unmounts it afterward.
"""

from __future__ import annotations

import argparse
import errno
import os
from pathlib import Path

from fuse import FUSE, FuseOSError, Operations


class PassthroughWithoutDirectoryFsync(Operations):
    def __init__(self, root: Path) -> None:
        self.root = root.resolve(strict=True)

    def path(self, path: str) -> str:
        return os.fspath(self.root / path.removeprefix("/"))

    def access(self, path: str, mode: int) -> None:
        if not os.access(self.path(path), mode):
            raise FuseOSError(errno.EACCES)

    def chmod(self, path: str, mode: int) -> int:
        return os.chmod(self.path(path), mode)

    def chown(self, path: str, uid: int, gid: int) -> int:
        return os.chown(self.path(path), uid, gid)

    def create(self, path: str, mode: int, fi=None) -> int:
        flags = getattr(fi, "flags", os.O_RDWR | os.O_CREAT | os.O_EXCL)
        # fusepy 3.0.1's FUSE2 callback does not pass ``fi`` on every Python
        # version.  The acceptance workload creates O_RDWR/O_EXCL temporaries;
        # preserve that stronger behavior instead of falling back to O_WRONLY.
        flags = (flags | os.O_RDWR | os.O_CREAT) & ~os.O_WRONLY
        return os.open(self.path(path), flags, mode)

    def flush(self, path: str, fh: int) -> None:
        os.fsync(fh)

    def fsync(self, path: str, datasync: int, fh: int) -> None:
        (os.fdatasync if datasync else os.fsync)(fh)

    def fsyncdir(self, path: str, datasync: int, fh: int) -> None:
        raise FuseOSError(errno.EINVAL)

    @staticmethod
    def attributes(info: os.stat_result) -> dict[str, int | float]:
        names = (
            "st_atime",
            "st_blksize",
            "st_blocks",
            "st_ctime",
            "st_dev",
            "st_gid",
            "st_ino",
            "st_mode",
            "st_mtime",
            "st_nlink",
            "st_size",
            "st_uid",
        )
        return {name: getattr(info, name) for name in names}

    def getattr(self, path: str, fh=None) -> dict[str, int | float]:
        info = os.fstat(fh) if fh is not None else os.lstat(self.path(path))
        return self.attributes(info)

    def fgetattr(self, path: str, fh: int) -> dict[str, int | float]:
        return self.attributes(os.fstat(fh))

    def link(self, target: str, source: str) -> None:
        os.link(self.path(source), self.path(target))

    def mkdir(self, path: str, mode: int) -> None:
        os.mkdir(self.path(path), mode)

    def open(self, path: str, flags: int) -> int:
        return os.open(self.path(path), flags)

    def read(self, path: str, size: int, offset: int, fh: int) -> bytes:
        return os.pread(fh, size, offset)

    def readdir(self, path: str, fh: int) -> list[str]:
        return [".", "..", *os.listdir(self.path(path))]

    def readlink(self, path: str) -> str:
        return os.readlink(self.path(path))

    def release(self, path: str, fh: int) -> None:
        os.close(fh)

    def rename(self, old: str, new: str) -> None:
        os.rename(self.path(old), self.path(new))

    def rmdir(self, path: str) -> None:
        os.rmdir(self.path(path))

    def statfs(self, path: str) -> dict[str, int]:
        info = os.statvfs(self.path(path))
        names = (
            "f_bavail",
            "f_bfree",
            "f_blocks",
            "f_bsize",
            "f_favail",
            "f_ffree",
            "f_files",
            "f_flag",
            "f_frsize",
            "f_namemax",
        )
        return {name: getattr(info, name) for name in names}

    def truncate(self, path: str, length: int, fh=None) -> None:
        with open(self.path(path), "r+b") as target:
            target.truncate(length)

    def unlink(self, path: str) -> None:
        os.unlink(self.path(path))

    def utimens(self, path: str, times=None) -> None:
        os.utime(self.path(path), times)

    def write(self, path: str, data: bytes, offset: int, fh: int) -> int:
        return os.pwrite(fh, data, offset)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("backing", type=Path)
    parser.add_argument("mountpoint", type=Path)
    args = parser.parse_args()
    if not args.backing.is_dir() or not args.mountpoint.is_dir():
        parser.error("backing and mountpoint must already be directories")
    FUSE(
        PassthroughWithoutDirectoryFsync(args.backing),
        os.fspath(args.mountpoint),
        foreground=True,
        nothreads=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
