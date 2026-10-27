from __future__ import annotations

import asyncio
import logging
import signal

from .alerts import Alerter
from .config import Config
from .events import EventLog
from .http_service import start_http
from .shell import Identity
from .ssh_service import start_ssh


async def _main() -> None:
    cfg = Config.from_env()
    log = EventLog(cfg.log_path, cfg.sensor_id, on_event=Alerter(cfg))
    ident = Identity(cfg.sensor_id)
    servers = [await start_ssh(cfg, log, ident), await start_http(cfg, log)]
    log.emit("sensor_start", ssh_port=cfg.ssh_port, http_port=cfg.http_port, persona=ident.hostname)
    logging.info("sentinel up: ssh=%s http=%s persona=%s", cfg.ssh_port, cfg.http_port, ident.hostname)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    try:
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, stop.set)
    except NotImplementedError:
        # Windows asyncio does not support signal handlers in the default event loop.
        # The server still runs; shutdown falls back to Ctrl+C / process termination.
        pass
    await stop.wait()
    for s in servers:
        s.close()
    for s in servers:
        try:
            await asyncio.wait_for(s.wait_closed(), 5)
        except asyncio.TimeoutError:
            pass
    log.emit("sensor_stop")


def run() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    asyncio.run(_main())


if __name__ == "__main__":
    run()
