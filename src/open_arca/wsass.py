import logging
logger = logging.getLogger(__name__)

from typing import Optional

from cryptography import x509
from cryptography.x509 import Certificate
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from .paths import paths


class WSASS:
    """
    Autogestor de certificados para Servicios Web en los ambientes de homologación (Testing).
    Permite crear certificados de prueba y definir las autorizaciones de acceso para los diferentes
    Web Services de testing de ARCA
    """

    def __init__(self, organization_name: str, common_name: str, serial_number: int):
        self.organization_name = organization_name
        self.common_name = common_name
        self.serial_number = serial_number

        self._private_key: Optional[RSAPrivateKey] = None
        self.private_key_path = paths.credentials_testing / "private_key.pem"

        self._certificate_signing_request: Optional[Certificate] = None
        self.certificate_signing_request_path = paths.credentials_testing / "certificate_signing_request.pem"

        if not self.private_key_path.exists():
            self.__generate_private_key()
        self._private_key = self.__load_private_key()

        if not self.certificate_signing_request_path.exists():
            self.__generate_certificate_signing_request()
        self._certificate_signing_request = self.__load_certificate_signing_request()

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
            logger.error(f"Al generar la clave privada: {error} - {type(error)}")
            raise

    def __load_private_key(self) -> RSAPrivateKey:
        logger.info("Cargando clave privada...")

        filepath = f"{paths.credentials_testing}/private_key.pem"
        try:
            with open(filepath, "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None
                )

            logger.info("Clave privada cargada con éxito.")
            return private_key
        except Exception as error:
            logger.error(f"Al cargar clave privada: {error} - {type(error)}")
            raise

    def __generate_certificate_signing_request(self):
        logger.info("Generando certificate signing request...")
        try:
            certificate_signing_request = x509.CertificateSigningRequestBuilder() \
            .subject_name(
                x509.Name([
                    x509.NameAttribute(NameOID.COUNTRY_NAME, "AR"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.organization_name),
                    x509.NameAttribute(NameOID.COMMON_NAME, self.common_name),
                    x509.NameAttribute(NameOID.SERIAL_NUMBER, f"CUIT {self.serial_number}")
                ])
            ) \
            .sign(self._private_key, hashes.SHA256())

            filepath = f"{paths.credentials_testing}/certificate_signing_request.pem"
            with open(filepath, "wb") as csr_file:
                csr_file.write(
                    certificate_signing_request.public_bytes(serialization.Encoding.PEM)
                )
            logger.info("Certificate signing request generado exitosamente.")
        except Exception as error:
            logger.error(f"Al generar el certificate signing request: {error} - {type(error)}")
            raise

    def __load_certificate_signing_request(self) -> Certificate:
        logger.info("Cargando certificate signing request...")

        filepath = f"{paths.credentials_testing}/certificate_signing_request.pem"
        try:
            with open(filepath, "rb") as csr_file:
                certificate_signing_request = x509.load_pem_x509_csr(csr_file.read())

            logger.info("Certificate signing request cargado con éxito.")
            return certificate_signing_request
        except ValueError as error:
            logger.error(f"(ValueError) Al cargar certificate signing request: {error}")
            raise
        except Exception as error:
            logger.error(f"Al cargar certificate signing request: {error} - {type(error)}")
            raise
