"""Refuse every open/write under the NSS-home live receipt store.

dir_fd-relative paths are resolved via /proc/self/fd/<n> or refused.
truncate, chmod, utime and rmdir are wrapped. subprocess is a stated
limit (same as the PLAN-R4 lease guard): a child process is not wrapped.
"""

from __future__ import annotations

import builtins
import io
import os
from pathlib import Path
import shutil

from kilix_license.errors import LiveStoreForbidden
from kilix_license.paths import is_under_live_store, live_store_root

_installed = False
_orig_open = builtins.open
_orig_io_open = io.open
_orig_os_open = os.open
_orig_os_mkdir = os.mkdir
_orig_os_makedirs = os.makedirs
_orig_os_replace = os.replace
_orig_os_rename = os.rename
_orig_os_remove = os.remove
_orig_os_unlink = os.unlink
_orig_os_link = os.link
_orig_os_symlink = os.symlink
_orig_os_truncate = os.truncate
_orig_os_chmod = os.chmod
_orig_os_utime = os.utime
_orig_os_rmdir = os.rmdir
_orig_shutil_copyfile = shutil.copyfile
_orig_shutil_copy = shutil.copy
_orig_shutil_copy2 = shutil.copy2
_orig_shutil_move = shutil.move
_orig_shutil_copytree = shutil.copytree


def live_root() -> Path:
    return live_store_root()


def _resolve(path: object, *, dir_fd: int | None = None) -> str | None:
    if path is None:
        return None
    if isinstance(path, int):
        try:
            return os.readlink(f"/proc/self/fd/{path}")
        except OSError:
            return None
    text = os.fsdecode(path)
    if not text:
        return None
    if os.path.isabs(text):
        return text
    if dir_fd is not None:
        try:
            base = os.readlink(f"/proc/self/fd/{dir_fd}")
        except OSError as exc:
            raise LiveStoreForbidden(
                f"dir_fd path refused (unresolvable fd {dir_fd}): {text}"
            ) from exc
        return os.path.join(base, text)
    return text


def _check(path: object, *, dir_fd: int | None = None) -> None:
    text = _resolve(path, dir_fd=dir_fd)
    if not text:
        return
    if is_under_live_store(text):
        raise LiveStoreForbidden(f"live store path refused: {text}")


def _wrap_open(file, *args, **kwargs):
    _check(file)
    return _orig_io_open(file, *args, **kwargs)


def _wrap_os_open(path, flags, mode=0o777, *, dir_fd=None):
    _check(path, dir_fd=dir_fd)
    if dir_fd is None:
        return _orig_os_open(path, flags, mode)
    return _orig_os_open(path, flags, mode, dir_fd=dir_fd)


def _wrap_mkdir(path, mode=0o777, *, dir_fd=None):
    _check(path, dir_fd=dir_fd)
    if dir_fd is None:
        return _orig_os_mkdir(path, mode)
    return _orig_os_mkdir(path, mode, dir_fd=dir_fd)


def _wrap_makedirs(name, mode=0o777, exist_ok=False):
    _check(name)
    return _orig_os_makedirs(name, mode, exist_ok=exist_ok)


def _wrap_replace(src, dst, *, src_dir_fd=None, dst_dir_fd=None):
    _check(src, dir_fd=src_dir_fd)
    _check(dst, dir_fd=dst_dir_fd)
    return _orig_os_replace(
        src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd
    )


def _wrap_rename(src, dst, *, src_dir_fd=None, dst_dir_fd=None):
    _check(src, dir_fd=src_dir_fd)
    _check(dst, dir_fd=dst_dir_fd)
    return _orig_os_rename(src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)


def _wrap_remove(path, *, dir_fd=None):
    _check(path, dir_fd=dir_fd)
    if dir_fd is None:
        return _orig_os_remove(path)
    return _orig_os_remove(path, dir_fd=dir_fd)


def _wrap_unlink(path, *, dir_fd=None):
    _check(path, dir_fd=dir_fd)
    if dir_fd is None:
        return _orig_os_unlink(path)
    return _orig_os_unlink(path, dir_fd=dir_fd)


def _wrap_link(src, dst, *, src_dir_fd=None, dst_dir_fd=None, follow_symlinks=True):
    _check(src, dir_fd=src_dir_fd)
    _check(dst, dir_fd=dst_dir_fd)
    return _orig_os_link(
        src,
        dst,
        src_dir_fd=src_dir_fd,
        dst_dir_fd=dst_dir_fd,
        follow_symlinks=follow_symlinks,
    )


def _wrap_symlink(src, dst, target_is_directory=False, *, dir_fd=None):
    _check(dst, dir_fd=dir_fd)
    if dir_fd is None:
        return _orig_os_symlink(src, dst, target_is_directory)
    return _orig_os_symlink(src, dst, target_is_directory, dir_fd=dir_fd)


def _wrap_truncate(path, length):
    _check(path)
    return _orig_os_truncate(path, length)


def _wrap_chmod(path, mode, *, dir_fd=None, follow_symlinks=True):
    _check(path, dir_fd=dir_fd)
    kwargs = {}
    if dir_fd is not None:
        kwargs["dir_fd"] = dir_fd
    if follow_symlinks is not True:
        kwargs["follow_symlinks"] = follow_symlinks
    return _orig_os_chmod(path, mode, **kwargs)


def _wrap_utime(path, times=None, *, ns=None, dir_fd=None, follow_symlinks=True):
    _check(path, dir_fd=dir_fd)
    kwargs = {}
    if ns is not None:
        kwargs["ns"] = ns
    if dir_fd is not None:
        kwargs["dir_fd"] = dir_fd
    if follow_symlinks is not True:
        kwargs["follow_symlinks"] = follow_symlinks
    return _orig_os_utime(path, times, **kwargs)


def _wrap_rmdir(path, *, dir_fd=None):
    _check(path, dir_fd=dir_fd)
    if dir_fd is None:
        return _orig_os_rmdir(path)
    return _orig_os_rmdir(path, dir_fd=dir_fd)


def _wrap_copyfile(src, dst, follow_symlinks=True):
    _check(src)
    _check(dst)
    return _orig_shutil_copyfile(src, dst, follow_symlinks=follow_symlinks)


def _wrap_copy(src, dst, follow_symlinks=True):
    _check(src)
    _check(dst)
    return _orig_shutil_copy(src, dst, follow_symlinks=follow_symlinks)


def _wrap_copy2(src, dst, follow_symlinks=True):
    _check(src)
    _check(dst)
    return _orig_shutil_copy2(src, dst, follow_symlinks=follow_symlinks)


def _wrap_move(src, dst, copy_function=shutil.copy2):
    _check(src)
    _check(dst)
    return _orig_shutil_move(src, dst, copy_function=copy_function)


def _wrap_copytree(*args, **kwargs):
    if args:
        _check(args[0])
    if len(args) > 1:
        _check(args[1])
    if "src" in kwargs:
        _check(kwargs["src"])
    if "dst" in kwargs:
        _check(kwargs["dst"])
    return _orig_shutil_copytree(*args, **kwargs)


def install() -> None:
    global _installed
    if _installed:
        return
    builtins.open = _wrap_open
    io.open = _wrap_open
    os.open = _wrap_os_open
    os.mkdir = _wrap_mkdir
    os.makedirs = _wrap_makedirs
    os.replace = _wrap_replace
    os.rename = _wrap_rename
    os.remove = _wrap_remove
    os.unlink = _wrap_unlink
    os.link = _wrap_link
    os.symlink = _wrap_symlink
    os.truncate = _wrap_truncate
    os.chmod = _wrap_chmod
    os.utime = _wrap_utime
    os.rmdir = _wrap_rmdir
    shutil.copyfile = _wrap_copyfile
    shutil.copy = _wrap_copy
    shutil.copy2 = _wrap_copy2
    shutil.move = _wrap_move
    shutil.copytree = _wrap_copytree
    _orig_write_text = Path.write_text
    _orig_write_bytes = Path.write_bytes
    _orig_touch = Path.touch
    _orig_path_open = Path.open
    _orig_path_mkdir = Path.mkdir

    def _wrap_write_text(self, *args, **kwargs):
        _check(self)
        return _orig_write_text(self, *args, **kwargs)

    def _wrap_write_bytes(self, *args, **kwargs):
        _check(self)
        return _orig_write_bytes(self, *args, **kwargs)

    def _wrap_touch(self, *args, **kwargs):
        _check(self)
        return _orig_touch(self, *args, **kwargs)

    def _wrap_path_open(self, *args, **kwargs):
        _check(self)
        return _orig_path_open(self, *args, **kwargs)

    def _wrap_path_mkdir(self, *args, **kwargs):
        _check(self)
        return _orig_path_mkdir(self, *args, **kwargs)

    Path.write_text = _wrap_write_text
    Path.write_bytes = _wrap_write_bytes
    Path.touch = _wrap_touch
    Path.open = _wrap_path_open
    Path.mkdir = _wrap_path_mkdir
    _installed = True
