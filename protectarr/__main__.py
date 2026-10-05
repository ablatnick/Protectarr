import logging
import os

import uvicorn

from . import config
from .web import create_app


def main() -> None:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = config.load()
    # Docker creates a missing bind-mount folder owned by root, which a non-root container can't write to.
    if not os.access(cfg.data_dir, os.W_OK):
        logging.getLogger("protectarr").error(
            "Can't write to the data folder %s (running as uid %s). If Docker created the folder for you, it's owned "
            "by root: create it yourself before the first start (mkdir -p protectarr/config protectarr/quarantine) "
            "or chown it to the user Protectarr runs as, then start Protectarr again.", cfg.data_dir, os.getuid())
        raise SystemExit(1)
    uvicorn.run(create_app(cfg), host="0.0.0.0", port=cfg.port, log_level="warning")


if __name__ == "__main__":
    main()
