from __future__ import annotations

import ctypes
import json
import os
import re
import subprocess
from ctypes import wintypes
from pathlib import Path
from typing import Any, Iterable

import pefile

from .models import Game, PatcherError, PROXY_NAMES


BODYCAM_APP_ID = "2406770"
BODYCAM_EXE = Path("Bodycam/Binaries/Win64/Bodycam-Win64-Shipping.exe")
MAX_PE_SIZE = 1024 * 1024 * 1024
MAX_BODYCAM_SETTINGS_SIZE = 256 * 1024
MAX_EXE_RESULTS = 512
MAX_SCAN_ENTRIES = 20_000
MAX_IMPORTS = 4096
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000 if os.name == "nt" else 0)

_EXCLUDED_EXE_PARTS = (
    "crashreport",
    "crashpad",
    "epicwebhelper",
    "unrealcefsubprocess",
    "redist",
    "redistributable",
    "prereq",
    "installer",
    "unins",
)
_ANTICHEAT_MARKERS = {
    "Easy Anti-Cheat": ("easyanticheat", "easy anti cheat"),
    "BattlEye": ("battleye", "beservice"),
    "Epic Online Services Anti-Cheat": ("eosanticheat", "eos anti cheat"),
    "ACE Anti-Cheat": ("anti-cheat expert", "ace-guard", "aceguard"),
    "XIGNCODE": ("xigncode", "xhunter"),
    "Ricochet": ("randgrid", "ricochet"),
}
_BODYCAM_GRAPHICS_KEYS = {
    "FG Method": "fg_method",
    "Upscaling Method": "upscaling_method",
    "DLSS Frames": "dlss_frames",
    "UI Method": "ui_method",
}


def _vdf_tokens(text: str) -> list[str]:
    """Tokenize Valve's quoted KeyValues format, including escaped strings."""
    tokens: list[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char.isspace():
            index += 1
            continue
        if text.startswith("//", index):
            newline = text.find("\n", index + 2)
            index = len(text) if newline < 0 else newline + 1
            continue
        if char in "{}":
            tokens.append(char)
            index += 1
            continue
        if char != '"':
            end = index + 1
            while end < len(text) and not text[end].isspace() and text[end] not in "{}":
                end += 1
            tokens.append(text[index:end])
            index = end
            continue
        index += 1
        value: list[str] = []
        while index < len(text):
            char = text[index]
            if char == '"':
                index += 1
                break
            if char == "\\" and index + 1 < len(text):
                escaped = text[index + 1]
                replacement = {"n": "\n", "r": "\r", "t": "\t", "\\": "\\", '"': '"'}.get(escaped)
                if replacement is None:
                    value.extend(("\\", escaped))
                else:
                    value.append(replacement)
                index += 2
                continue
            value.append(char)
            index += 1
        tokens.append("".join(value))
    return tokens


def _parse_vdf(text: str) -> dict[str, Any]:
    tokens = _vdf_tokens(text.lstrip("\ufeff"))
    position = 0

    def parse_object(expect_close: bool = False) -> dict[str, Any]:
        nonlocal position
        result: dict[str, Any] = {}
        while position < len(tokens):
            token = tokens[position]
            position += 1
            if token == "}":
                if expect_close:
                    return result
                raise ValueError("unexpected closing brace")
            if token == "{":
                raise ValueError("missing key before object")
            key = token
            if position >= len(tokens):
                raise ValueError("missing value")
            value = tokens[position]
            position += 1
            if value == "{":
                result[key] = parse_object(True)
            elif value == "}":
                raise ValueError("missing value before closing brace")
            else:
                result[key] = value
        if expect_close:
            raise ValueError("unclosed object")
        return result

    return parse_object()


def _read_vdf(path: Path) -> dict[str, Any]:
    return _parse_vdf(path.read_text(encoding="utf-8", errors="replace"))


def _steam_roots() -> list[Path]:
    candidates: list[Path] = []
    if os.name == "nt":
        try:
            import winreg

            keys = (
                (winreg.HKEY_CURRENT_USER, r"Software\Valve\Steam", "SteamPath"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Valve\Steam", "InstallPath"),
            )
            for hive, key_name, value_name in keys:
                try:
                    with winreg.OpenKey(hive, key_name) as key:
                        candidates.append(Path(winreg.QueryValueEx(key, value_name)[0]))
                except OSError:
                    pass
        except (ImportError, OSError):
            pass
    program_files = os.environ.get("ProgramFiles(x86)")
    if program_files:
        candidates.append(Path(program_files) / "Steam")
    return _unique_existing_paths(candidates)


def _unique_existing_paths(paths: Iterable[Path]) -> list[Path]:
    result: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        try:
            resolved = path.expanduser().resolve()
        except OSError:
            continue
        key = os.path.normcase(str(resolved))
        if key not in seen and resolved.is_dir():
            seen.add(key)
            result.append(resolved)
    return result


def _steam_libraries() -> list[Path]:
    libraries: list[Path] = []
    for steam_root in _steam_roots():
        libraries.append(steam_root)
        library_file = steam_root / "steamapps" / "libraryfolders.vdf"
        if not library_file.is_file():
            continue
        try:
            parsed = _read_vdf(library_file)
            folders = parsed.get("libraryfolders", parsed.get("LibraryFolders", {}))
            if isinstance(folders, dict):
                for value in folders.values():
                    if isinstance(value, dict):
                        value = value.get("path")
                    if isinstance(value, str):
                        libraries.append(Path(value))
        except (OSError, ValueError):
            continue
    return _unique_existing_paths(libraries)


def _manifest_game(manifest: Path) -> Game | None:
    try:
        parsed = _read_vdf(manifest)
    except (OSError, ValueError):
        return None
    state = parsed.get("AppState", parsed.get("appstate"))
    if not isinstance(state, dict):
        return None
    app_id = str(state.get("appid", "")).strip()
    install_dir = str(state.get("installdir", "")).strip()
    if not app_id or not install_dir:
        return None
    install_root = manifest.parent / "common" / install_dir
    if not install_root.is_dir():
        return None
    exes = find_game_exes(install_root)
    if not exes:
        return None
    if app_id == BODYCAM_APP_ID:
        expected = install_root / BODYCAM_EXE
        exe = expected.resolve() if expected.is_file() else exes[0]
    else:
        exe = exes[0]
    return Game(
        exe=exe,
        name=str(state.get("name", install_dir)),
        app_id=app_id,
        build_id=str(state.get("buildid", "")).strip() or None,
        install_root=install_root.resolve(),
    )


def discover_steam_games() -> list[Game]:
    games: list[Game] = []
    seen: set[str] = set()
    for library in _steam_libraries():
        steamapps = library / "steamapps"
        try:
            manifests = sorted(steamapps.glob("appmanifest_*.acf"))
        except OSError:
            continue
        for manifest in manifests:
            game = _manifest_game(manifest)
            if game is None:
                continue
            key = os.path.normcase(str(game.exe))
            if key not in seen:
                seen.add(key)
                games.append(game)
    games.sort(key=lambda game: (game.app_id != BODYCAM_APP_ID, game.name.casefold()))
    return games


def _exe_priority(path: Path, root: Path) -> tuple[int, int, str]:
    relative = path.relative_to(root).as_posix().casefold()
    if relative == BODYCAM_EXE.as_posix().casefold():
        return (0, len(path.parts), relative)
    shipping = "-win64-shipping.exe" in path.name.casefold()
    root_level = path.parent == root
    return (1 if shipping else 2 if root_level else 3, len(path.parts), relative)


def find_game_exes(folder: Path) -> list[Path]:
    folder = Path(folder)
    if not folder.is_dir():
        return []
    result: list[Path] = []
    try:
        iterator = folder.rglob("*.exe")
        for scanned, path in enumerate(iterator):
            if scanned >= MAX_SCAN_ENTRIES:
                break
            try:
                relative_parts = path.relative_to(folder).parts
            except ValueError:
                continue
            lowered = "/".join(relative_parts).casefold()
            if any(marker in lowered for marker in _EXCLUDED_EXE_PARTS):
                continue
            if path.is_file():
                result.append(path.resolve())
                if len(result) >= MAX_EXE_RESULTS:
                    break
    except (OSError, PermissionError):
        pass
    return sorted(result, key=lambda path: _exe_priority(path, folder.resolve()))


def game_for_exe(exe: Path) -> Game:
    exe = Path(exe).resolve()
    if not exe.is_file() or exe.suffix.casefold() != ".exe":
        raise PatcherError("Выбранный файл игры не найден или не является EXE.")
    for parent in exe.parents:
        if parent.name.casefold() != "common" or parent.parent.name.casefold() != "steamapps":
            continue
        try:
            install_dir = exe.relative_to(parent).parts[0]
        except (ValueError, IndexError):
            break
        install_root = parent / install_dir
        for manifest in parent.parent.glob("appmanifest_*.acf"):
            game = _manifest_game(manifest)
            if game and game.install_root and _same_path(game.install_root, install_root):
                selected = exe
                launcher = game.install_root / "Bodycam.exe"
                rendering_exe = game.install_root / BODYCAM_EXE
                if game.app_id == BODYCAM_APP_ID and _same_path(exe, launcher) and rendering_exe.is_file():
                    selected = rendering_exe.resolve()
                return Game(selected, game.name, game.app_id, game.build_id, game.install_root)
        break
    return Game(exe=exe, name=exe.stem, install_root=exe.parent)


def _directory_entries(pe: pefile.PE, name: str) -> list[str]:
    result: list[str] = []
    entries = getattr(pe, name, None)
    for entry in entries or ():
        raw_name = getattr(entry, "dll", b"")
        if isinstance(raw_name, bytes):
            decoded = raw_name.decode("ascii", errors="ignore")
        else:
            decoded = str(raw_name)
        decoded = decoded.strip().casefold()
        if decoded and decoded not in result:
            result.append(decoded)
        if len(result) >= MAX_IMPORTS:
            break
    return result


def inspect_exe(path: Path) -> dict[str, Any]:
    path = Path(path)
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise PatcherError(f"Не удалось открыть EXE игры: {exc}") from exc
    if path.suffix.casefold() != ".exe" or not path.is_file():
        raise PatcherError("Выбранный файл не является EXE игры.")
    if size <= 0 or size > MAX_PE_SIZE:
        raise PatcherError("Размер EXE игры выходит за безопасные пределы проверки.")
    pe: pefile.PE | None = None
    try:
        pe = pefile.PE(str(path), fast_load=True)
        machine = int(pe.FILE_HEADER.Machine)
        if machine != pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]:
            raise PatcherError("Патчер поддерживает только 64-битные игры Windows (x64).")
        pe.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"],
            ]
        )
        return {
            "machine": machine,
            "imports": _directory_entries(pe, "DIRECTORY_ENTRY_IMPORT"),
            "delay_imports": _directory_entries(pe, "DIRECTORY_ENTRY_DELAY_IMPORT"),
        }
    except PatcherError:
        raise
    except (OSError, pefile.PEFormatError, ValueError) as exc:
        raise PatcherError("Файл не является корректным Windows EXE.") from exc
    finally:
        if pe is not None:
            pe.close()


def gpu_info() -> dict[str, Any]:
    fallback = {"name": "NVIDIA GPU не обнаружена", "memory_mib": None, "compute_cap": None, "driver": None}
    command = [
        "nvidia-smi",
        "--query-gpu=name,memory.total,compute_cap,driver_version",
        "--format=csv,noheader,nounits",
    ]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=6,
            check=False,
            creationflags=CREATE_NO_WINDOW,
        )
    except (OSError, subprocess.TimeoutExpired):
        return fallback
    if completed.returncode != 0 or not completed.stdout.strip():
        return fallback
    fields = [field.strip() for field in completed.stdout.splitlines()[0].split(",")]
    if len(fields) != 4:
        return fallback
    try:
        memory_mib: int | None = int(round(float(fields[1])))
    except ValueError:
        memory_mib = None
    return {"name": fields[0], "memory_mib": memory_mib, "compute_cap": fields[2] or None, "driver": fields[3] or None}


def bodycam_graphics_settings() -> dict[str, str]:
    """Read a small allowlisted view of Bodycam's GVAS graphics settings."""
    local_app_data = os.environ.get("LOCALAPPDATA")
    if not local_app_data:
        return {}
    path = Path(local_app_data) / "Bodycam" / "Saved" / "SaveGames" / "GlobalUserSettings.sav"
    try:
        size = path.stat().st_size
        if size <= 0 or size > MAX_BODYCAM_SETTINGS_SIZE:
            return {}
        content = path.read_bytes()
    except OSError:
        return {}
    if len(content) != size:
        return {}

    offset = 0
    while True:
        start = content.find(b'{"', offset)
        if start < 0:
            return {}
        end = content.find(b"\0", start)
        if end < 0:
            return {}
        offset = start + 2
        try:
            candidate = json.loads(content[start:end].decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if not isinstance(candidate, dict) or not all(key in candidate for key in _BODYCAM_GRAPHICS_KEYS):
            continue
        normalized: dict[str, str] = {}
        valid = True
        for source_key, output_key in _BODYCAM_GRAPHICS_KEYS.items():
            setting = candidate.get(source_key)
            value = setting.get("valueName") if isinstance(setting, dict) else None
            if not isinstance(value, str) or not value.strip() or len(value) > 128:
                valid = False
                break
            normalized[output_key] = value.strip()
        if valid:
            return normalized


def _same_path(first: Path, second: Path) -> bool:
    return os.path.normcase(os.path.abspath(str(first))) == os.path.normcase(os.path.abspath(str(second)))


class _UnqueryableGameProcess(OSError):
    pass


def _process_names_native() -> dict[int, str]:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    TH32CS_SNAPPROCESS = 0x00000002
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", wintypes.WCHAR * 260),
        ]

    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    kernel32.Process32FirstW.restype = wintypes.BOOL
    kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    kernel32.Process32NextW.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == INVALID_HANDLE_VALUE:
        raise ctypes.WinError(ctypes.get_last_error())
    names: dict[int, str] = {}
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)
        success = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while success:
            names[int(entry.th32ProcessID)] = entry.szExeFile.casefold()
            success = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)
    return names


def _running_process_paths_native(target_names: set[str] | None = None) -> list[Path]:
    if os.name != "nt":
        raise OSError("Windows process API unavailable")
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi.EnumProcesses.argtypes = [ctypes.POINTER(wintypes.DWORD), wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    psapi.EnumProcesses.restype = wintypes.BOOL
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    process_ids = (wintypes.DWORD * 16384)()
    bytes_returned = wintypes.DWORD()
    if not psapi.EnumProcesses(process_ids, ctypes.sizeof(process_ids), ctypes.byref(bytes_returned)):
        raise ctypes.WinError(ctypes.get_last_error())
    if bytes_returned.value >= ctypes.sizeof(process_ids):
        raise OSError("process list exceeded safe enumeration limit")
    count = bytes_returned.value // ctypes.sizeof(wintypes.DWORD)
    paths: list[Path] = []
    process_names = _process_names_native() if target_names else {}
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    for pid in process_ids[:count]:
        if not pid:
            continue
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            if process_names.get(int(pid), "") in (target_names or set()):
                raise _UnqueryableGameProcess(process_names[int(pid)])
            continue
        try:
            capacity = wintypes.DWORD(32768)
            buffer = ctypes.create_unicode_buffer(capacity.value)
            if kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(capacity)):
                paths.append(Path(buffer.value))
        finally:
            kernel32.CloseHandle(handle)
    return paths


def _running_process_paths_powershell() -> list[Path]:
    script = (
        "@(Get-CimInstance Win32_Process | Where-Object {$_.ExecutablePath} | "
        "Select-Object -ExpandProperty ExecutablePath) | ConvertTo-Json -Compress"
    )
    completed = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=6,
        check=False,
        creationflags=CREATE_NO_WINDOW,
    )
    if completed.returncode != 0:
        raise OSError("PowerShell process query failed")
    parsed = json.loads(completed.stdout or "[]")
    if isinstance(parsed, str):
        parsed = [parsed]
    if not isinstance(parsed, list):
        raise ValueError("unexpected process query response")
    return [Path(value) for value in parsed if isinstance(value, str) and value]


def ensure_game_closed(game: Game) -> None:
    targets = [game.exe]
    if game.install_root and game.install_root.is_dir():
        targets.extend(find_game_exes(game.install_root))
    target_names = {target.name.casefold() for target in targets}
    try:
        running = _running_process_paths_native(target_names)
    except _UnqueryableGameProcess as exc:
        raise PatcherError(
            f"Процесс {exc} запущен, но Windows не разрешает проверить его путь. Закройте игру перед изменением файлов."
        ) from exc
    except (OSError, ValueError):
        try:
            running = _running_process_paths_powershell()
        except (OSError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
            raise PatcherError("Не удалось безопасно проверить, закрыта ли игра. Закройте игру и повторите попытку.") from exc
    for process_path in running:
        if any(_same_path(process_path, target) for target in targets):
            raise PatcherError(f"Игра запущена: {process_path.name}. Закройте её перед изменением файлов.")


def detect_anticheat(game: Game) -> list[str]:
    root = game.install_root or game.exe.parent
    if not root.is_dir():
        return []
    evidence: set[str] = set()
    try:
        for path in root.rglob("*"):
            try:
                relative = path.relative_to(root).as_posix().casefold()
            except ValueError:
                continue
            for label, markers in _ANTICHEAT_MARKERS.items():
                if any(marker in relative for marker in markers):
                    evidence.add(f"{label}: {path.relative_to(root)}")
            if len(evidence) >= 32:
                break
    except (OSError, PermissionError):
        pass
    if os.name == "nt":
        try:
            import winreg

            services = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services")
            with services:
                index = 0
                while index < 16_384 and len(evidence) < 32:
                    try:
                        service_name = winreg.EnumKey(services, index)
                    except OSError:
                        break
                    index += 1
                    try:
                        with winreg.OpenKey(services, service_name) as service:
                            image_path = str(winreg.QueryValueEx(service, "ImagePath")[0])
                    except OSError:
                        continue
                    expanded = os.path.expandvars(image_path).casefold().replace("/", "\\")
                    root_text = str(root.resolve()).casefold().replace("/", "\\")
                    if root_text not in expanded:
                        continue
                    searchable = f"{service_name} {image_path}".casefold()
                    for label, markers in _ANTICHEAT_MARKERS.items():
                        if any(marker in searchable for marker in markers):
                            evidence.add(f"{label}: служба {service_name}")
        except (ImportError, OSError):
            pass
    return sorted(evidence, key=str.casefold)


def loaded_modules(pid: int) -> list[str]:
    if os.name != "nt" or pid <= 0:
        return []
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    TH32CS_SNAPMODULE = 0x00000008
    TH32CS_SNAPMODULE32 = 0x00000010
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    class MODULEENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("th32ModuleID", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("GlblcntUsage", wintypes.DWORD),
            ("ProccntUsage", wintypes.DWORD),
            ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)),
            ("modBaseSize", wintypes.DWORD),
            ("hModule", wintypes.HMODULE),
            ("szModule", wintypes.WCHAR * 256),
            ("szExePath", wintypes.WCHAR * 260),
        ]

    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.Module32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
    kernel32.Module32FirstW.restype = wintypes.BOOL
    kernel32.Module32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
    kernel32.Module32NextW.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if snapshot == INVALID_HANDLE_VALUE:
        return []
    modules: list[str] = []
    try:
        entry = MODULEENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)
        success = kernel32.Module32FirstW(snapshot, ctypes.byref(entry))
        while success:
            modules.append(entry.szExePath or entry.szModule)
            success = kernel32.Module32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)
    return modules


__all__ = [
    "Game",
    "PatcherError",
    "PROXY_NAMES",
    "detect_anticheat",
    "bodycam_graphics_settings",
    "discover_steam_games",
    "ensure_game_closed",
    "find_game_exes",
    "game_for_exe",
    "gpu_info",
    "inspect_exe",
    "loaded_modules",
]
