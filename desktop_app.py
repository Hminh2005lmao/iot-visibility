from __future__ import annotations

import os
import socket
import threading
import time
import urllib.request
from pathlib import Path

from werkzeug.serving import make_server

from api.app import app

try:
    import webview
except ImportError as exc:  # pragma: no cover
    raise SystemExit(
        "Missing dependency: pywebview. Run scripts/install.ps1 first."
    ) from exc


class FlaskServerThread(threading.Thread):
    def __init__(self, host: str, port: int):
        super().__init__(daemon=True)
        self._server = make_server(host, port, app, threaded=True)
        self._ctx = app.app_context()
        self._ctx.push()

    def run(self) -> None:
        self._server.serve_forever()

    def shutdown(self) -> None:
        self._server.shutdown()


def pick_port(preferred: int = 5000) -> int:
    for port in range(preferred, preferred + 50):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    raise RuntimeError("No free local port available in 5000-5049.")


def wait_server_ready(url: str, timeout_sec: float = 12.0) -> None:
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1.0) as resp:
                if resp.status < 500:
                    return
        except Exception:
            time.sleep(0.2)
    raise RuntimeError("Desktop app could not start embedded server in time.")


def main() -> None:
    root = Path(__file__).resolve().parent
    os.chdir(root)

    host = "127.0.0.1"
    port = pick_port(5000)
    url = f"http://{host}:{port}/"

    server = FlaskServerThread(host, port)
    server.start()
    wait_server_ready(url)

    try:
        webview.create_window(
            title="IoT Security Scanner",
            url=url,
            width=1380,
            height=900,
            min_size=(1100, 720),
            resizable=True,
        )
        webview.start()
    finally:
        server.shutdown()


if __name__ == "__main__":
    main()
