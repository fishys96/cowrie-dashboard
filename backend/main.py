import asyncio
import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from backend import store, tailer
from backend.config import settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("dashboard.main")

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"


class ConnectionManager:
    def __init__(self) -> None:
        self._connections: set[WebSocket] = set()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._connections.add(ws)

    def disconnect(self, ws: WebSocket) -> None:
        self._connections.discard(ws)

    async def broadcast(self, message: dict) -> None:
        if not self._connections:
            return
        payload = json.dumps(message, default=str)
        dead = []
        for ws in self._connections:
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self._connections.discard(ws)


manager = ConnectionManager()


async def _on_log_line(raw_line: str) -> None:
    event = await store.ingest_line(raw_line)
    if event is not None:
        await manager.broadcast({"type": "event", "data": event})


async def _stats_broadcaster() -> None:
    while True:
        await asyncio.sleep(2)
        await manager.broadcast({"type": "stats", "data": store.get_stats()})


async def _on_caught_up() -> None:
    store.end_catchup()


@asynccontextmanager
async def lifespan(app: FastAPI):
    store.init_db()
    tail_task = asyncio.create_task(
        tailer.run(
            settings.cowrie_log_path,
            settings.poll_interval,
            _on_log_line,
            on_caught_up=_on_caught_up,
            from_start=settings.replay_on_start,
        )
    )
    stats_task = asyncio.create_task(_stats_broadcaster())
    logger.info("Dashboard started, tailing %s", settings.cowrie_log_path)
    try:
        yield
    finally:
        tail_task.cancel()
        stats_task.cancel()


app = FastAPI(title="Cowrie Attack Dashboard", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(FRONTEND_DIR / "index.html")


@app.get("/api/snapshot")
async def snapshot() -> dict:
    return store.get_snapshot()


@app.get("/api/attacker/{ip}")
async def attacker_detail(ip: str) -> dict:
    detail = store.get_attacker_detail(ip)
    if detail is None:
        raise HTTPException(status_code=404, detail="Unknown attacker IP")
    return detail


@app.get("/api/commands/search")
async def command_search(q: str = "") -> dict:
    return store.search_commands(q)


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket) -> None:
    await manager.connect(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(ws)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("backend.main:app", host=settings.host, port=settings.port, reload=False)
