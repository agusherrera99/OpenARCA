import logging
logger = logging.getLogger(__name__)

import xml.etree.ElementTree as ET
from xml.etree.ElementTree import ElementTree


from pathlib import Path, PosixPath


class ProjectPath:
    """
    Administra la creación y obtención de las rutas disponibles en el sistema
    """

    def __init__(self):
        self._root = Path(__file__).resolve().parent
        self.dirs = []

    def build(self):
        self._create_dirs()
        self._create_keeps()

    @property
    def root(self):
        return self._root

    def _create_dirs(self):
        for dir in self.dirs:
            dir.mkdir(parents=True, exist_ok=True)

    def _create_keeps(self):
        for dir in self.dirs:
            Path(dir / ".keep").touch(exist_ok=True)


class LogPath(ProjectPath):
    def __init__(self):
        super().__init__()
        self._path = self._root / "logs"

        self.dirs = [self._path]

        self.build()

    @property
    def path(self):
        return self._path


class CredentialPath(ProjectPath):
    def __init__(self):
        super().__init__()
        self._path = self._root / "credentials"
        self._testing = self._path / "testing"
        self._production = self._path / "production"

        self.dirs = [self._path, self._testing]

        self.build()

    @property
    def path(self):
        return self._path

    @property
    def testing(self):
        return self._testing

    @property
    def production(self):
        return self._production


class AccessTicketPath(ProjectPath):
    def __init__(self):
        super().__init__()
        self._path = self._root / "access_tickets"
        self._testing = self._path / "testing"
        self._production = self._path / "production"

        self.dirs = [self._path, self._testing]

        self.build()

    @property
    def path(self):
        return self._path

    @property
    def testing(self):
        return self._testing

    @property
    def production(self):
        return self._production


class TemplatePath(ProjectPath):
    def __init__(self):
        super().__init__()
        self._path = self._root / "templates"

        self.dirs = [self._path]

        self.build()

    @property
    def path(self):
        return self._path

    def get(self, name: str) -> ElementTree:
        try:
            filepath: Posix = self._path / name
            tree = ET.parse(filepath)
            return tree
        except Exception as error:
            logger.error(f"Al intentar obtener un template: {error} - {type(error)}")
            raise
