"""Async tail of the Cowrie JSON log, tolerant of logrotate (rename+recreate or truncate)."""

import asyncio
import logging
import os
from typing import AsyncIterator, Awaitable, Callable

logger = logging.getLogger("dashboard.tailer")


async def tail_file(path: str, poll_interval: float) -> AsyncIterator[str]:
    """Yield complete new lines appended to `path`, starting from end-of-file."""
    file = None
    inode = None

    while True:
        if file is None:
            try:
                file = open(path, "r", encoding="utf-8", errors="replace")
            except FileNotFoundError:
                logger.warning("Cowrie log not found at %s, retrying...", path)
                await asyncio.sleep(poll_interval * 4)
                continue
            inode = os.fstat(file.fileno()).st_ino
            file.seek(0, os.SEEK_END)

        pos = file.tell()
        line = file.readline()

        if line and line.endswith("\n"):
            yield line
            continue

        if line:
            # Partial line -- writer hasn't flushed the newline yet, rewind and retry.
            file.seek(pos)
            await asyncio.sleep(poll_interval)
            continue

        # No data: check whether the file was rotated (renamed+recreated or truncated).
        try:
            st = os.stat(path)
        except FileNotFoundError:
            file.close()
            file = None
            await asyncio.sleep(poll_interval)
            continue

        if st.st_ino != inode or st.st_size < pos:
            logger.info("Detected rotation/truncation of %s, reopening", path)
            file.close()
            file = None
            continue

        await asyncio.sleep(poll_interval)


async def run(path: str, poll_interval: float, on_line: Callable[[str], Awaitable[None]]) -> None:
    async for line in tail_file(path, poll_interval):
        try:
            await on_line(line)
        except Exception:
            logger.exception("Error handling log line")
