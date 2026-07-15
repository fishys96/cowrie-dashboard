"""Async tail of the Cowrie JSON log, tolerant of logrotate (rename+recreate or truncate).

On boot the tailer can either seek to the end (live only) or read from the beginning so that
events logged while the dashboard process was stopped get ingested too ("catch-up"). It emits a
one-time `("caught_up", None)` item the first time it drains the pre-existing content, so the
caller can switch off its dedup guard and treat everything after as live.
"""

import asyncio
import logging
import os
from typing import AsyncIterator, Awaitable, Callable, Optional, Tuple

logger = logging.getLogger("dashboard.tailer")


async def tail_file(path: str, poll_interval: float, from_start: bool) -> AsyncIterator[Tuple[str, Optional[str]]]:
    """Yield ("line", <line>) for each complete log line, and ("caught_up", None) once, the first
    time the pre-existing backlog is fully drained. If `from_start` is False, start at EOF (live
    only) and signal caught-up immediately on the first idle poll."""
    file = None
    inode = None
    caught_up = False

    while True:
        if file is None:
            try:
                file = open(path, "r", encoding="utf-8", errors="replace")
            except FileNotFoundError:
                logger.warning("Cowrie log not found at %s, retrying...", path)
                await asyncio.sleep(poll_interval * 4)
                continue
            inode = os.fstat(file.fileno()).st_ino
            # Seek to end only when NOT catching up. When catching up we read from position 0 so
            # the whole current file (including the downtime backlog) flows through.
            if not from_start:
                file.seek(0, os.SEEK_END)

        pos = file.tell()
        line = file.readline()

        if line and line.endswith("\n"):
            yield ("line", line)
            continue

        if line:
            # Partial line -- writer hasn't flushed the newline yet, rewind and retry.
            file.seek(pos)

        # No complete line available: we've drained everything currently in the file.
        if not caught_up:
            caught_up = True
            yield ("caught_up", None)

        # Check whether the file was rotated (renamed+recreated or truncated).
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
            # Reopen reads the fresh file from the start; caught_up stays True so we don't
            # re-enter catch-up mode for a mid-run rotation.
            continue

        await asyncio.sleep(poll_interval)


async def run(
    path: str,
    poll_interval: float,
    on_line: Callable[[str], Awaitable[None]],
    on_caught_up: Optional[Callable[[], Awaitable[None]]] = None,
    from_start: bool = True,
) -> None:
    async for kind, payload in tail_file(path, poll_interval, from_start):
        if kind == "caught_up":
            if on_caught_up is not None:
                try:
                    await on_caught_up()
                except Exception:
                    logger.exception("Error in caught-up handler")
        else:
            try:
                await on_line(payload)
            except Exception:
                logger.exception("Error handling log line")
