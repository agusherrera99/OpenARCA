import logging
logger = logging.getLogger(__name__)

from .routes import LogPath


def main() -> None:
    logging.basicConfig(
        filename=f"{LogPath().path}/OpenARCA.log",
        level=logging.DEBUG,
        format='%(asctime)s | %(filename)s.%(funcName)s (line: %(lineno)d) - %(levelname)s: %(message)s'
    )
