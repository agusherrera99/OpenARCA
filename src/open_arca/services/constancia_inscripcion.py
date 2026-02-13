import logging
logger = logging.getLogger(__name__)

from zeep import Client

from ..wsaa import WSAA


class ARCAService:
    def __init__(self, wsaa_instance: WSAA, wsdl_url: str, service_name: str):
        self.wsaa = wsaa_instance
        self.wsdl = wsdl_url
        self.client = Client(self.wsdl)
        self.service_name = service_name

    def _get_auth_payload(self):
        token, sign = self.wsaa.get_ticket_access_authentications(self.service_name)
        return {
            "token": token,
            "sign": sign,
            "cuitRepresentada": self.wsaa.serial_number
        }


class ConstanciaInscripcion(ARCAService):
    """
    Datos de un contribuyente relacionados con su
    constancia de inscripción.
    """

    def __init__(self, wsaa_instance: WSAA, testing: bool = False):
        wsdl = "https://awshomo.afip.gov.ar/sr-padron/webservices/personaServiceA5?WSDL" if testing else "https://aws.afip.gov.ar/sr-padron/webservices/personaServiceA5?WSDL"
        service_name: str = "ws_sr_constancia_inscripcion"
        super().__init__(wsaa_instance, wsdl, service_name)

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

        auth = self._get_auth_payload()
        return self.client.service.getPersona_v2(
            token=auth["token"],
            sign=auth["sign"],
            cuitRepresentada=auth["cuitRepresentada"],
            idPersona=cuit
        )

    def obtener_personas(self, cuits: list[int]):
        """
        Devuelve idénticos datos que el método getPersona_v2, pero
        para una lista de hasta 250 claves tributarias.
        """

        auth = self._get_auth_payload()
        return self.client.service.getPersonaList_v2(
            token=auth["token"],
            sign=auth["sign"],
            cuitRepresentada=auth["cuitRepresentada"],
            idPersona=cuits
        )
