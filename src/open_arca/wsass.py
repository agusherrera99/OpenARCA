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
        self.private_key_path = paths.credentials_testing / "private_key.pem"

        if not self.private_key_path.exists():
            self.__generate_private_key()
        self._private_key = self.__load_private_key()

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
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )

            filepath = f"{paths.credentials_testing}/private_key.pem"
            with open(filepath, "wb") as key_file:
                key_file.write(private_key_bytes)

            logger.info("Clave privada generada exitosamente.")
        except Exception as error:
            logger.warning(f"Error al generar la clave privada: {error}")
            raise

    def __load_private_key(self) -> RSAPrivateKey:
        logger.info("Cargando clave privada...")

        filepath = f"{paths.credentials_testing}/private_key.pem"
        with open(filepath, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None
            )

        logger.info("Clave privada cargada con éxito.")
        return private_key
