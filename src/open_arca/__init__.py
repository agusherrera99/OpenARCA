import logging
logger = logging.getLogger(__name__)

from .routes import LogPath, CredentialPath
from .services import ConstanciaInscripcion
from .wsaa import get_wsaa_client


class OpenARCA:
    def __init__(
        self,
        organization_name: str,
        common_name: str,
        serial_number: int,
        testing: bool = False
    ):
        self.wsaa_instance = get_wsaa_client(
            testing,
            organization_name=organization_name,
            common_name=common_name,
            serial_number=serial_number
        )
        self.constancia_inscripcion = ConstanciaInscripcion(self.wsaa_instance, testing=testing)


def main() -> None:
    logging.basicConfig(
        filename=f"{LogPath().path}/OpenARCA.log",
        level=logging.DEBUG,
        format='%(asctime)s | %(filename)s.%(funcName)s (line: %(lineno)d) - %(levelname)s: %(message)s'
    )
