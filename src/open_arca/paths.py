from pathlib import Path


class Paths:
    """
    Administra la creación y obtención de las rutas disponibles en el sistema
    """

    def __init__(self):
        self._root = Path(__file__).resolve().parent
        self._logs = self._root / "logs"
        self._credentials = self._root / "credentials"
        self._credentials_testing = self._credentials / "testing"

        self.dirs = [self._logs, self._credentials, self._credentials_testing]

        self.__create_dirs()
        self.__create_keeps()

    @property
    def root(self):
        return self._root

    @property
    def logs(self):
        return self._logs

    @property
    def credentials(self):
        return self._credentials

    @property
    def credentials_testing(self):
        return self._credentials_testing

    def __create_dirs(self):
        for dir in self.dirs:
            dir.mkdir(exist_ok=True)

    def __create_keeps(self):
        for dir in self.dirs:
            Path(dir / ".keep").touch(exist_ok=True)

paths = Paths()
