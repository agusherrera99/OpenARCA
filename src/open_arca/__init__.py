import logging
logger = logging.getLogger(__name__)


def main() -> None:
    logging.basicConfig(
        filename=f"{paths.logs}/OpenARCA.log",
        level=logging.DEBUG,
        format='%(asctime)s | %(filename)s.%(funcName)s (line: %(lineno)d) - %(levelname)s: %(message)s'
    )
