import logging
logger = logging.getLogger(__name__)

from zeep import Client

from ..wsaa import Homologacion


# NOTE: Por ahora solo trabajamos con homologación, más adelante agrego producción
class ConstanciaInscripcion:
    """
    Datos de un contribuyente relacionados con su
    constancia de inscripción.
    """

    def __init__(self):
        self.wsdl = "https://awshomo.afip.gov.ar/sr-padron/webservices/personaServiceA5?WSDL"
        self.client = Client(self.wsdl)
        self.service_name: str = "ws_sr_constancia_inscripcion"

    def dummy(self):
        """
        Verifica el estado y la disponibilidad de los
        elementos principales del servicio (aplicación, autenticación y base de datos).
        """

        logger.info("Chequeando dummy...")
        response = self.client.service.dummy()
        logger.info(response)

        return response

    def obtener_persona(self, cuit: int):
        """
        Devuelve el detalle de todos los datos, correspondientes a la
        constancia de inscripción, del contribuyente solicitado.
        """

        homologacion = Homologacion("Agustín Herrera", "OpenARCAtest", 20419264300)
        token, sign = homologacion.get_ticket_access_authentications(self.service_name)
        result = self.client.service.getPersona_v2(
            token=token,
            sign=sign,
            cuitRepresentada=homologacion.serial_number,
            idPersona=cuit
        )
        return result

    def obtener_personas(self, cuits: list[int]):
        """
        Devuelve idénticos datos que el método getPersona_v2, pero
        para una lista de hasta 250 claves tributarias.
        """

        homologacion = Homologacion("Agustin Herrera", "OpenARCAtest", 20419264300)
        token, sign = homologacion.get_ticket_access_authentications(self.service_name)
        results = self.client.service.getPersonaList_v2(
            token=token,
            sign=sign,
            cuitRepresentada=homologacion.serial_number,
            idPersona=cuits
        )
        return results
