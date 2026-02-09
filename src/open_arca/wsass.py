import logging
logger = logging.getLogger(__name__)

from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from .paths import paths


class WSASS:
    """
    Autogestor de certificados para Servicios Web en los ambientes de homologación (Testing).
    Permite crear certificados de prueba y definir las autorizaciones de acceso para los diferentes
    Web Services de testing de ARCA
    """

    def __init__(self):
        self._private_key: Optional[RSAPrivateKey] = None

        if self._private_key is None:
            self.__generate_private_key()

    @property
    def private_key(self) -> Optional[RSAPrivateKey]:
        return self._private_key

    def __generate_private_key(self):
        logger.info("Generando clave privada...")
        try:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )

            private_key_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )

            filepath = f"{paths.credentials_testing}/private_key.pem"
            with open(filepath, "wb") as file:
                file.write(private_key_bytes)

            logger.info("Clave privada generada exitosamente.")
        except Exception as error:
            logger.warning(f"Error al generar la clave privada: {error}")
            raise
