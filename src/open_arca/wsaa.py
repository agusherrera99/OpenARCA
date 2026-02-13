import base64
import json
import random

import logging
logger = logging.getLogger(__name__)

import xml.etree.ElementTree as ET

from datetime import datetime, timedelta
from pathlib import PosixPath
from time import ctime
from typing import ClassVar, Optional
from zoneinfo import ZoneInfo

from cryptography import x509
from cryptography.x509 import Certificate
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import pkcs7
from ntplib import NTPClient
from zeep import Client

from .routes import AccessTicketPath, CredentialPath, TemplatePath


class WSAA:
    """
    Autogestor de certificados para Servicios Web.
    Permite crear certificados y definir las autorizaciones de acceso para los diferentes
    Web Services de ARCA
    """
    ACCESS_TICKET_PATH: ClassVar[AccessTicketPath] = AccessTicketPath()
    CREDENTIAL_PATH: ClassVar[CredentialPath] = CredentialPath()
    TEMPLATE_PATH: ClassVar[TemplatePath] = TemplatePath()

    def __init__(self, organization_name: str, common_name: str, serial_number: int):
        self.organization_name = organization_name
        self.common_name = common_name
        self.serial_number = serial_number

        self.client: Optional[Client] = None

        self._private_key: Optional[RSAPrivateKey] = None
        self.private_key_path: Optional[PosixPath] = self.CREDENTIAL_PATH.path / "private_key.pem"

        self._certificate_signing_request: Optional[Certificate] = None
        self.certificate_signing_request_path: Optional[PosixPath] = self.CREDENTIAL_PATH.path / "certificate_signing_request.pem"

        self._certificate: Optional[Certificate] = None
        self.certificate_path: Optional[PosixPath] = None

        self.access_ticket_path: Optional[PosixPath] = None

    @property
    def private_key(self) -> Optional[RSAPrivateKey]:
        return self._private_key

    @property
    def certificate_signing_request(self) -> Optional[Certificate]:
        return self._certificate_signing_request

    @property
    def certificate(self) -> Optional[Certificate]:
        return self._certificate

    def build(self):
        if not self.private_key_path.exists():
            self._generate_private_key()
        else:
            self._private_key = self._load_private_key()

        if not self.certificate_signing_request_path.exists():
            self._generate_certificate_signing_request()
        else:
            self._certificate_signing_request = self._load_certificate_signing_request()

    def get_ticket_access_authentications(self, service_name: str):
        filename = f"ta_{service_name}.json"
        cache_file = self.access_ticket_path / filename

        if cache_file.exists():
            with open(cache_file, "r") as file:
                ticket_access_data = json.load(file)

            expiration = datetime.fromisoformat(ticket_access_data['expiration_time'])
            if self._get_ntp_synced_datetime() < (expiration - timedelta(minutes=10)):
                logger.info(f"Usando ticket cacheado para {service_name}")
                return ticket_access_data['token'], ticket_access_data['sign']

        return self._request_new_ticket_access_authentications(service_name)

    def _get_ntp_synced_datetime(self) -> datetime:
        logging.info("Obteniendo fecha sincronizada...")
        try:
            client = NTPClient()
            response = client.request("time.afip.gov.ar", version=3)

            date_string = ctime(response.tx_time)
            format_string = "%a %b %d %H:%M:%S %Y"

            naive_datetime = datetime.strptime(date_string, format_string)
            aware_datetime = naive_datetime.replace(tzinfo=ZoneInfo("America/Argentina/Buenos_Aires"))

            logging.info("Fecha sincronizada obtenida correctamente.")
            return aware_datetime
        except Exception as error:
            logging.error(f"Al obtener la fecha sincronizada: {error} - {type(error)}")
            raise

    def _generate_private_key(self):
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
            self._private_key = private_key

            with open(self.private_key_path, "wb") as key_file:
                key_file.write(private_key_bytes)

            logger.info("Clave privada generada exitosamente.")
        except Exception as error:
            logger.error(f"Al generar la clave privada: {error} - {type(error)}")
            raise

    def _load_private_key(self) -> RSAPrivateKey:
        logger.info("Cargando clave privada...")
        try:
            with open(self.private_key_path, "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None
                )

            logger.info("Clave privada cargada con éxito.")
            return private_key
        except Exception as error:
            logger.error(f"Al cargar clave privada: {error} - {type(error)}")
            raise

    def _generate_certificate_signing_request(self):
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
            self._certificate_signing_request = certificate_signing_request

            with open(self.certificate_signing_request_path, "wb") as csr_file:
                csr_file.write(
                    certificate_signing_request.public_bytes(serialization.Encoding.PEM)
                )
            logger.info("Certificate signing request generado exitosamente.")
        except Exception as error:
            logger.error(f"Al generar el certificate signing request: {error} - {type(error)}")
            raise

    def _load_certificate_signing_request(self) -> Certificate:
        logger.info("Cargando certificate signing request...")
        try:
            with open(self.certificate_signing_request_path, "rb") as csr_file:
                certificate_signing_request = x509.load_pem_x509_csr(csr_file.read())

            logger.info("Certificate signing request cargado con éxito.")
            return certificate_signing_request
        except ValueError as error:
            logger.error(f"(ValueError) Al cargar certificate signing request: {error}")
            raise
        except Exception as error:
            logger.error(f"Al cargar certificate signing request: {error} - {type(error)}")
            raise

    def _require_certificate_bytes(self) -> bytes:
        raws = []
        while True:
            raw = input()
            if not raw:
                break
            raws.append(raw)
        certificate_bytes = bytes("\n".join(raws), "utf-8")
        return certificate_bytes

    def _save_certificate(self, pem_data: bytes) -> Optional[bool]:
        logger.info("Guardando certificado...")
        try:
            certificate = x509.load_pem_x509_certificate(pem_data)
            self._certificate = certificate

            with open(self.certificate_path, "wb") as crt_file:
                crt_file.write(certificate.public_bytes(serialization.Encoding.PEM))
            logger.info("Certificado guardado exitosamente.")
            return True
        except Exception as error:
            logger.error(f"Al guardar certificado: {error} - {type(error)}")
            raise

    def _load_certificate(self) -> Certificate:
        logger.info("Cargando certificado...")
        try:
            with open(self.certificate_path, "rb") as csr_file:
                certificate = x509.load_pem_x509_certificate(csr_file.read())

            logger.info("Certificado cargado con éxito.")
            return certificate
        except ValueError as error:
            logger.error(f"(ValueError) Al cargar certificado: {error}")
            raise
        except Exception as error:
            logger.error(f"Al cargar certificado: {error} - {type(error)}")
            raise

    def _create_access_request_ticket(self, service_name: str) -> str:
        now = self._get_ntp_synced_datetime() - timedelta(minutes=5)
        generation_time: str = now.isoformat().split(".")[0]
        expiration_time: str = (now + timedelta(hours=12)).isoformat().split(".")[0]
        unique_id = str(random.randint(1000, 999_999))

        tree = self.TEMPLATE_PATH.get("login_ticket_request.xml")
        root = tree.getroot()
        header = root.find(".//header")
        header.find(".//uniqueId").text = unique_id
        header.find(".//generationTime").text = generation_time
        header.find(".//expirationTime").text = expiration_time

        service = tree.find(".//service")
        service.text = service_name
        result = ET.tostring(root, encoding="utf-8", method="xml", xml_declaration=True)

        return result

    def _sign_access_request_ticket(self, service_name: str):
        options = [pkcs7.PKCS7Options.Binary]
        builder = pkcs7.PKCS7SignatureBuilder(
            self._create_access_request_ticket(service_name),
            [(self.certificate, self.private_key, hashes.SHA256(), None)]
        )
        return builder.sign(serialization.Encoding.DER, options)

    def _request_new_ticket_access_authentications(self, service_name: str):
        logger.info("Solicitando nuevo ticket de acceso para {service_name}...")
        signed_access_request_ticket = self._sign_access_request_ticket(service_name)

        response = self.client.service.loginCms(
            base64.b64encode(signed_access_request_ticket).decode("utf-8")
        )

        tree = ET.fromstring(response.encode("utf-8"))
        token = tree.find(".//token").text
        sign = tree.find(".//sign").text
        generation_time = tree.find(".//generationTime").text
        expiration_time = tree.find(".//expirationTime").text

        cache_file = self.access_ticket_path / f"ta_{service_name}.json"
        with open(cache_file, "w") as file:
            json.dump({
                "token": token,
                "sign": sign,
                "generation_time": generation_time,
                "expiration_time": expiration_time
            }, file)

        return token, sign


class Produccion(WSAA):
    def __init__(self, organization_name: str, common_name: str, serial_number: int):
        super().__init__(organization_name, common_name, serial_number)
        self.wsdl: str = "https://wsaa.afip.gov.ar/ws/services/LoginCms?WSDL"
        self.client = Client(self.wsdl)

        self.certificate_path = self.CREDENTIAL_PATH.production / "certificate.pem"
        self.access_ticket_path = self.ACCESS_TICKET_PATH.production

        self.build()

        if not self.certificate_path.exists():
            self.save_certificate()
        self._certificate = self._load_certificate()

    def save_certificate(self):
        public_certificate_signing_request = self.certificate_signing_request \
            .public_bytes(
                encoding=serialization.Encoding.PEM
            ).decode()

        print("Si el servicio 'Administración de Certificados Digitales' no está habilidado, ingresa a https://serviciosweb.afip.gob.ar/claveFiscal/adminRel/main.aspx para habilitarlo.")
        print("Nueva Relación -> Buscar -> Seleccionar el servicio 'Administración de Certificados Digitales' -> Buscar -> Ingresar CUIT/CUIL/CDI del Representante -> Buscar -> Confirmar -> Salir del sistema\n")

        print("Ingresar a https://serviciosweb.afip.gob.ar/clavefiscal/adminrel/verCertificado.aspx")
        print("Seleccionar contribuyente -> Agregar alias -> Elegir un nombre para el alias")
        print("Sube este archivo CSR:")
        print(self.certificate_signing_request_path)
        print("Agregar Alias -> Ver -> Descargar Certificado")

        print("Pega acá el contenido del certificado descargado:")
        certificate_bytes = self._require_certificate_bytes()
        if self._save_certificate(certificate_bytes):
            print("Certificado guardado exitosamente.")


class Homologacion(WSAA):
    """Ambiente de testing."""

    def __init__(self, organization_name: str, common_name: str, serial_number: int):
        super().__init__(organization_name, common_name, serial_number)
        self.wsdl: str = "https://wsaahomo.afip.gov.ar/ws/services/LoginCms?WSDL"
        self.client = Client(self.wsdl)

        self.certificate_path = self.CREDENTIAL_PATH.testing / "certificate.pem"
        self.access_ticket_path = self.ACCESS_TICKET_PATH.testing

        self.build()

        if not self.certificate_path.exists():
            self.save_certificate()
        self._certificate = self._load_certificate()


    def save_certificate(self):
        public_certificate_signing_request = self.certificate_signing_request \
            .public_bytes(
                encoding=serialization.Encoding.PEM
            ).decode()

        print("Ingresa a https://wsass-homo.afip.gob.ar/wsass/portal/main.aspx")
        print("Nuevo certificado -> Completa el 'Nombre simbólico del DN' -> Pega este Certificate Signing Request\n")
        print(f"{public_certificate_signing_request}\n")

        print("Pega acá el resultado luego de presionar 'Crear DN y obtener certificado':")
        certificate_bytes = self._require_certificate_bytes()
        if self._save_certificate(certificate_bytes):
            print("Certificado guardado exitosamente.")


def get_wsaa_client(testing: bool, **kwargs) -> WSAA:
    if testing:
        return Homologacion(**kwargs)
    return Produccion(**kwargs)
