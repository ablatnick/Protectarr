import logging
import os

import uvicorn

from . import config
from .web import create_app


def main() -> None:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = config.load()
    uvicorn.run(create_app(cfg), host="0.0.0.0", port=cfg.port, log_level="warning")


if __name__ == "__main__":
    main()
