"""Optional native macOS menu-bar controller for the local MacTrace server."""

from __future__ import annotations

import logging
import threading
import webbrowser

import uvicorn

from mactrace.api import create_app
from mactrace.config import Settings

log = logging.getLogger(__name__)


class ServerController:
    def __init__(self, mode: str = "live", port: int = 8000) -> None:
        self.mode = mode
        self.port = port
        self.server: uvicorn.Server | None = None
        self.thread: threading.Thread | None = None

    def start(self) -> None:
        if self.thread and self.thread.is_alive():
            return
        settings = Settings.load(mode=self.mode)
        config = uvicorn.Config(
            create_app(settings),
            host="127.0.0.1",
            port=self.port,
            log_level="info",
        )
        self.server = uvicorn.Server(config)
        self.thread = threading.Thread(
            target=self.server.run,
            name="mactrace-local-server",
            daemon=True,
        )
        self.thread.start()

    def stop(self) -> None:
        if self.server:
            self.server.should_exit = True
        if self.thread:
            self.thread.join(timeout=5)
        self.server = None
        self.thread = None

    def restart(self, mode: str) -> None:
        self.stop()
        self.mode = mode
        self.start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"


def main() -> None:
    try:
        import rumps
    except ImportError as exc:
        raise SystemExit(
            'Menu-bar support is optional. Install it with: pip install -e ".[menubar]"'
        ) from exc

    class MacTraceMenuBar(rumps.App):
        def __init__(self) -> None:
            super().__init__("MT", title="MT", quit_button=None)
            self.controller = ServerController()
            self.controller.start()
            self.live_item = rumps.MenuItem("Live mode", callback=self.live_mode)
            self.demo_item = rumps.MenuItem("Demo mode", callback=self.demo_mode)
            self.live_item.state = 1
            self.menu = [
                rumps.MenuItem("Open dashboard", callback=self.open_dashboard),
                None,
                self.live_item,
                self.demo_item,
                None,
                rumps.MenuItem("Stop local server", callback=self.stop_server),
                rumps.MenuItem("Start local server", callback=self.start_server),
                None,
                rumps.MenuItem("Quit MacTrace", callback=self.quit_app),
            ]

        def open_dashboard(self, _sender) -> None:
            webbrowser.open(self.controller.url)

        def live_mode(self, _sender) -> None:
            self.controller.restart("live")
            self.live_item.state = 1
            self.demo_item.state = 0
            rumps.notification("MacTrace", "Live mode", "Local collection is running.")

        def demo_mode(self, _sender) -> None:
            self.controller.restart("demo")
            self.live_item.state = 0
            self.demo_item.state = 1
            rumps.notification("MacTrace", "Demo mode", "Synthetic replay is running.")

        def stop_server(self, _sender) -> None:
            self.controller.stop()

        def start_server(self, _sender) -> None:
            self.controller.start()

        def quit_app(self, _sender) -> None:
            self.controller.stop()
            rumps.quit_application()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    MacTraceMenuBar().run()


if __name__ == "__main__":
    main()
