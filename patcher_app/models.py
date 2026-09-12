from dataclasses import dataclass, field
from pathlib import Path


PROXY_NAMES = ("version.dll", "winmm.dll", "winhttp.dll", "dxgi.dll", "dinput8.dll")
INI_NAME = "dlssg_sm86.ini"
UPSTREAM = "sdli1995/dlssg_for_sm86"
BUNDLED_REVISION = "5f62ff44a9c08f9841fa605e7b7160f79ccd2c40"


class PatcherError(Exception):
    """An actionable error safe to display to the user."""


@dataclass(frozen=True)
class Bundle:
    root: Path
    revision: str
    label: str
    files: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Game:
    exe: Path
    name: str = "Игра"
    app_id: str | None = None
    build_id: str | None = None
    install_root: Path | None = None

    @property
    def directory(self) -> Path:
        return self.exe.parent
