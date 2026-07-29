"""MacTrace command line entrypoint."""

from __future__ import annotations

import argparse
import logging
import os

import uvicorn


def main() -> None:
    parser = argparse.ArgumentParser(description="Run MacTrace locally")
    parser.add_argument("--mode", choices=["live", "demo"], default="live")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--config", default=None)
    parser.add_argument("--log-level", default="info")
    args = parser.parse_args()
    os.environ["MACTRACE_MODE"] = args.mode
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    from .config import Settings
    from .api import create_app

    settings = Settings.load(path=None if args.config is None else __import__("pathlib").Path(args.config), mode=args.mode)
    uvicorn.run(create_app(settings), host=args.host, port=args.port, log_level=args.log_level)


if __name__ == "__main__":
    main()

