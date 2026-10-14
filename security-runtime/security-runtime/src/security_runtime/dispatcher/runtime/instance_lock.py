"""OS-owned dispatcher lock, released even when the process crashes."""
from __future__ import annotations

import os
from pathlib import Path


class DispatcherInstance:
    def __init__(self, config_path: Path) -> None:
        config = config_path.resolve()
        self.path = config.with_name(f".{config.name}.dispatcher.lock")
        self.handle = None

    def __enter__(self):
        handle = self.path.open("a+b")
        if self.path.stat().st_size == 0:
            handle.write(b" ")
            handle.flush()
        handle.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            handle.close()
            raise RuntimeError(f"Dispatcher already running for {self.path.name}; stop that instance first") from exc
        self.handle = handle
        return self

    def __exit__(self, *_args):
        if self.handle is not None:
            # Do not unlink: replacing a locked inode permits two owners on POSIX.
            self.handle.close()
            self.handle = None
