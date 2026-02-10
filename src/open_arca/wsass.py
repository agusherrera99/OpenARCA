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

        self._certificate: Optional[certificate] = None
        self.certificate_path = paths.credentials_testing / "certificate.pem"

        if not self.private_key_path.exists():
            self.__generate_private_key()
        self._private_key = self.__load_private_key()

        if not self.certificate_signing_request_path.exists():
            self.__generate_certificate_signing_request()
        self._certificate_signing_request = self.__load_certificate_signing_request()

        if not self.certificate_path.exists():
            self.save_certificate()
        self._certificate = self.__load_certificate()

    @property
    def private_key(self) -> Optional[RSAPrivateKey]:
        return self._private_key

    @property
    def certificate_signing_request(self) -> Optional[Certificate]:
        return self._certificate_signing_request

    @property
    def certificate(self) -> Optional[Certificate]:
        return self._certificate

    def save_certificate(self):
        public_certificate_signing_request = self.certificate_signing_request \
            .public_key() \
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

        print("Entra a https://wsass-homo.afip.gob.ar/wsass/portal/main.aspx")
        print("Nuevo certificado -> Completa el 'Nombre simbólico del DN' -> Pega este Certificate Signing Request\n")
        print(f"{public_certificate_signing_request.decode('utf-8')}\n")

        raws = []
        print("Pega acá el resultado luego de presionar 'Crear DN y obtener certificado':")
        while True:
            raw = input()
            if not raw:
                break
            raws.append(raw)
        certificate_bytes = bytes("\n".join(raws), "utf-8")
        if self.__save_certificate(certificate_bytes):
            print("Certificado guardado exitosamente.")

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

    def __save_certificate(self, pem_data: bytes) -> Optional[bool]:
        logger.info("Guardando certificado...")
        try:
            certificate = x509.load_pem_x509_certificate(pem_data)
            filepath = f"{paths.credentials_testing}/certificate.pem"
            with open(filepath, "wb") as crt_file:
                crt_file.write(certificate.public_bytes(serialization.Encoding.PEM))
            logger.info("Certificado guardado exitosamente.")
            return True
        except Exception as error:
            logger.error(f"Al guardar certificado: {error} - {type(error)}")
            raise

    def __load_certificate(self) -> Certificate:
        logger.info("Cargando certificado...")

        filepath = f"{paths.credentials_testing}/certificate.pem"
        try:
            with open(filepath, "rb") as csr_file:
                certificate = x509.load_pem_x509_certificate(csr_file.read())

            logger.info("Certificado cargado con éxito.")
            return certificate
        except ValueError as error:
            logger.error(f"(ValueError) Al cargar certificado: {error}")
            raise
        except Exception as error:
            logger.error(f"Al cargar certificado: {error} - {type(error)}")
            raise
