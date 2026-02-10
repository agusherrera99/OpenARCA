import logging
logger = logging.getLogger(__name__)

from zeep import Client

class ConstanciaInscripcion:
    def __init__(self, testing: bool = True):
        self.testing = testing
        self.wsdl = "https://awshomo.afip.gov.ar/sr-padron/webservices/personaServiceA5?WSDL" if self.testing else "https://aws.afip.gov.ar/sr-padron/webservices/personaServiceA5?WSDL"
        self.client = Client(self.wsdl)

    def dummy(self):
        logger.info("Chequeando dummy...")
        response = self.client.service.dummy()
        logger.info(response)

