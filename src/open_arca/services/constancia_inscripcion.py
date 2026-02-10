import logging
logger = logging.getLogger(__name__)

from zeep import Client

from ..wsaa import Homologacion


# NOTE: Por ahora solo trabajamos con homologación, más adelante agrego producción
class ConstanciaInscripcion:
    def __init__(self):
        self.wsdl = "https://awshomo.afip.gov.ar/sr-padron/webservices/personaServiceA5?WSDL"
        self.client = Client(self.wsdl)
        self.service_name: str = "ws_sr_constancia_inscripcion"

    def dummy(self):
        logger.info("Chequeando dummy...")
        response = self.client.service.dummy()
        logger.info(response)

        return response

    def obtener_información(self, cuit: str):
        homologacion = Homologacion("Agustín Herrera", "OpenARCAtest", "20419264300")
        token, sign = homologacion.get_ticket_access_authentications(self.service_name)
        result = self.client.service.getPersona_V2(
            token=token,
            sign=sign,
            cuitRepresentada=homologacion.serial_number,
            idPersona=cuit
        )
        return result
