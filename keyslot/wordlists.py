"""User passphrase lists beside the selected KeePassXC configuration."""
import os
from pathlib import Path
import stat
import tempfile

from .backend import VaultError


class WordListError(VaultError):
    pass


class WordLists:
    def __init__(self, startup):
        self.profile = getattr(startup, "storage", None)
        self.directory = (Path(self.profile.arguments[0][1]).parent / "wordlists" if self.profile
                          else startup.directory / "keyslot" / "wordlists")

    def check(self):
        if self.profile and str(Path(self.profile.arguments[0][1]).resolve()) != self.profile.paths["global"]:
            raise WordListError("The configuration link changed. Reopen Keyslot before managing word lists.")

    @staticmethod
    def fingerprint(info):
        return [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns]

    def entries(self):
        self.check()
        if not self.directory.exists():
            return []
        result = []
        for path in sorted(self.directory.iterdir(), key=lambda item: item.name.casefold()):
            if path.name.startswith("."):
                continue
            try:
                info = path.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISREG(info.st_mode):
                result.append({"name": path.name, "path": str(path), "revision": self.fingerprint(info)})
        return result

    def add(self, source, inspect, alive):
        self.check()
        source = Path(source)
        if not source.name or source.name.startswith("."):
            raise WordListError("Choose a word list with a visible file name.")
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor, name = tempfile.mkstemp(prefix=".keyslot-wordlist-", dir=self.directory)
        stage = Path(name)
        try:
            with os.fdopen(descriptor, "wb") as output:
                descriptor = os.open(source, os.O_RDONLY | os.O_NONBLOCK)
                with os.fdopen(descriptor, "rb") as stream:
                    if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                        raise WordListError("Choose a regular word-list file.")
                    while chunk := stream.read(1024 * 1024):
                        if not alive():
                            raise WordListError("Word-list import was cancelled.")
                        output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
            details = inspect(str(stage))
            self.check()
            if not alive():
                raise WordListError("Word-list import was cancelled.")
            # Never replace another copy or the selected source file.
            for index in range(10000):
                target = self.directory / (source.name if not index else f"{source.stem} ({index + 1}){source.suffix}")
                try:
                    os.link(stage, target)
                    self.sync()
                    return {"path": str(target), **details}
                except FileExistsError:
                    continue
            raise WordListError("Too many word lists have this name. Rename the source and try again.")
        finally:
            stage.unlink(missing_ok=True)

    def remove(self, entry):
        self.check()
        path = self.directory / entry["name"]
        if str(path) != entry["path"] or path.parent != self.directory:
            raise WordListError("Choose a list from this profile's word-list library.")
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or self.fingerprint(info) != entry["revision"]:
            raise WordListError("This word list changed. Reopen the library before removing it.")
        path.unlink()
        self.sync()

    def sync(self):
        descriptor = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
