"""Validated, revision-pinned DLSSG payload management."""

from __future__ import annotations

import configparser
import hashlib
import json
import os
import re
import shutil
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Callable

import pefile

from .models import BUNDLED_REVISION, INI_NAME, PROXY_NAMES, UPSTREAM, Bundle, PatcherError


NOTICE_NAME = "THIRD_PARTY_NOTICES.txt"
MANIFEST_NAME = "manifest.json"
REQUIRED_FILES = (*PROXY_NAMES, INI_NAME, NOTICE_NAME)
REMOTE_PATHS = {
    "version.dll": "version.dll",
    "winmm.dll": "altnative/winmm.dll",
    "winhttp.dll": "altnative/winhttp.dll",
    "dxgi.dll": "altnative/dxgi.dll",
    "dinput8.dll": "altnative/dinput8.dll",
    INI_NAME: INI_NAME,
    NOTICE_NAME: NOTICE_NAME,
}
README_PATH = "README.en.md"
API_HOST = "api.github.com"
RAW_HOST = "raw.githubusercontent.com"
MAX_FILE_SIZE = 64 * 1024 * 1024
MAX_TOTAL_SIZE = 300 * 1024 * 1024
HTTP_TIMEOUT = 20
HTTP_RETRIES = 2

_BUNDLED_SHA256 = {
    "version.dll": "c844646d835a7b88ed1382eea80403d38b433f8ac09cf92581c73698c44ae7c2",
    "winmm.dll": "1004dd4ee0edbe4e1af4c8c7b30d4786bea0f5e7c0412566996b4c2543ae7e36",
    "winhttp.dll": "1619839e4d1b6145ce9a587ba807f42e64f2b0984af9e81700d42ccf46ff7253",
    "dxgi.dll": "8d29eddbd7f1c3e272d07f94ab8812a80ef5b7aeb73923320bf9a432ddcf74c0",
    "dinput8.dll": "ef3c3d49c5b5c8a17289c24da9b22885570793d72f3db628fa500f9efdb20489",
    INI_NAME: "fd7f0722194e6e8d8c085327d9826effb411925a69a5e7549d70eff26a9f18b5",
    NOTICE_NAME: "2f57e223c3cfe951379da7c0df5a14f897387d63dd79aff583b22a78e9b276ac",
}

_PROXY_EXPORTS = {
    "version.dll": "GetFileVersionInfoW",
    "winmm.dll": "timeGetTime",
    "winhttp.dll": "WinHttpOpen",
    "dxgi.dll": "CreateDXGIFactory",
    "dinput8.dll": "DirectInput8Create",
}
_INI_LAYOUT = {
    "Compatibility": {"router", "kernelimage", "hardwarebilinear"},
    "FrameGeneration": {"maxgeneratedframes"},
    "Logging": {"level"},
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git_blob_sha1(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()


def _safe_manifest_files(value: object) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != set(REQUIRED_FILES):
        raise PatcherError("Манифест содержит неверный набор файлов.")
    result: dict[str, str] = {}
    for name, digest in value.items():
        if Path(name).name != name or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise PatcherError("Манифест содержит неверное имя файла или SHA-256.")
        result[name] = digest
    return result


def load_bundle(root: Path) -> Bundle:
    """Load a bundle manifest without trusting any path from that manifest."""
    root = Path(root)
    try:
        raw = json.loads((root / MANIFEST_NAME).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PatcherError(f"Не удалось прочитать манифест пакета: {exc}") from exc
    if not isinstance(raw, dict) or set(raw) != {"revision", "label", "files"}:
        raise PatcherError("Манифест пакета имеет неподдерживаемый формат.")
    revision = raw["revision"]
    label = raw["label"]
    if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise PatcherError("В манифесте указана неверная ревизия.")
    if not isinstance(label, str) or not label.strip() or len(label) > 100:
        raise PatcherError("В манифесте указана неверная метка версии.")
    return Bundle(root=root, revision=revision, label=label.strip(), files=_safe_manifest_files(raw["files"]))


def _validate_pe(path: Path, name: str) -> None:
    try:
        image = pefile.PE(str(path), fast_load=True)
        image.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
        )
    except (OSError, pefile.PEFormatError) as exc:
        raise PatcherError(f"{name}: файл не является корректной DLL.") from exc
    try:
        if image.FILE_HEADER.Machine != pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]:
            raise PatcherError(f"{name}: требуется 64-битная DLL x64.")
        if image.OPTIONAL_HEADER.Magic != 0x20B:
            raise PatcherError(f"{name}: требуется формат PE32+.")
        export_directory = getattr(image, "DIRECTORY_ENTRY_EXPORT", None)
        symbols = {
            symbol.name.decode("ascii", errors="ignore")
            for symbol in (export_directory.symbols if export_directory else ())
            if symbol.name
        }
        if _PROXY_EXPORTS[name] not in symbols or "NVSDK_NGX_D3D12_Init" not in symbols:
            raise PatcherError(f"{name}: отсутствуют обязательные экспорты proxy DLSSG.")
    finally:
        image.close()


def _validate_ini(path: Path) -> None:
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    try:
        with path.open("r", encoding="utf-8-sig") as stream:
            parser.read_file(stream)
    except (OSError, UnicodeError, configparser.Error) as exc:
        raise PatcherError(f"{INI_NAME}: неверный формат INI.") from exc
    if set(parser.sections()) != set(_INI_LAYOUT):
        raise PatcherError(f"{INI_NAME}: ожидаются только разделы Compatibility, FrameGeneration и Logging.")
    for section, expected in _INI_LAYOUT.items():
        if set(parser[section]) != expected:
            raise PatcherError(f"{INI_NAME}: неверный набор параметров в разделе {section}.")
    router = parser["Compatibility"]["router"]
    kernel = parser["Compatibility"]["kernelimage"]
    if router not in {"SM75", "SM86"} or kernel not in {"PTX", "Auto", "Cubin"}:
        raise PatcherError(f"{INI_NAME}: неподдерживаемый Router или KernelImage.")
    numeric = {
        "HardwareBilinear": (parser["Compatibility"]["hardwarebilinear"], {"0", "1"}),
        "MaxGeneratedFrames": (parser["FrameGeneration"]["maxgeneratedframes"], {"1", "2", "3"}),
        "Level": (parser["Logging"]["level"], {"0", "1", "2", "3"}),
    }
    for key, (value, allowed) in numeric.items():
        if value not in allowed:
            raise PatcherError(f"{INI_NAME}: неподдерживаемое значение {key}.")


def validate_bundle(bundle: Bundle) -> None:
    """Validate paths, hashes and the executable/configuration contract."""
    if set(bundle.files) != set(REQUIRED_FILES):
        raise PatcherError("Пакет содержит неверный набор файлов.")
    total = 0
    for name in REQUIRED_FILES:
        path = bundle.root / name
        try:
            size = path.stat().st_size
        except OSError as exc:
            raise PatcherError(f"В пакете отсутствует {name}.") from exc
        if not path.is_file() or size <= 0 or size > MAX_FILE_SIZE:
            raise PatcherError(f"{name}: недопустимый размер файла.")
        total += size
        if total > MAX_TOTAL_SIZE:
            raise PatcherError("Общий размер пакета превышает допустимый предел.")
        if _sha256(path) != bundle.files[name]:
            raise PatcherError(f"{name}: контрольная сумма SHA-256 не совпадает.")
    for name in PROXY_NAMES:
        _validate_pe(bundle.root / name, name)
    _validate_ini(bundle.root / INI_NAME)


def _write_manifest(root: Path, revision: str, label: str) -> Bundle:
    files = {name: _sha256(root / name) for name in REQUIRED_FILES}
    manifest = {"revision": revision, "label": label, "files": files}
    (root / MANIFEST_NAME).write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    bundle = Bundle(root=root, revision=revision, label=label, files=files)
    validate_bundle(bundle)
    return bundle


def create_bundled_payload(repo: Path, destination: Path) -> Bundle:
    """Build the flat payload embedded by PyInstaller from the checked-in files."""
    repo = Path(repo)
    destination = Path(destination)
    repo = repo.resolve()
    destination = destination.resolve()
    build_root = repo / "build"
    is_build_output = destination.is_relative_to(build_root)
    is_named_workspace = destination.name == "bundled-payload" and not repo.is_relative_to(destination)
    if destination == repo or repo.is_relative_to(destination) or not (is_build_output or is_named_workspace):
        raise PatcherError("Каталог встроенного пакета должен находиться в build или называться bundled-payload.")
    for name, relative in REMOTE_PATHS.items():
        source = repo / relative
        try:
            actual = _sha256(source)
        except OSError as exc:
            raise PatcherError(f"Не удалось проверить исходный файл {relative}: {exc}") from exc
        if actual != _BUNDLED_SHA256[name]:
            raise PatcherError(
                f"{relative}: файл не соответствует закреплённому Native 0.2.4 ({BUNDLED_REVISION[:8]})."
            )
    if destination.is_dir():
        try:
            existing = load_bundle(destination)
            validate_bundle(existing)
        except PatcherError:
            existing = None
        if (existing is not None and existing.revision == BUNDLED_REVISION
                and existing.files == _BUNDLED_SHA256):
            return existing
    destination.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=f".{destination.name}-", dir=destination.parent))
    previous: Path | None = None
    try:
        for name, relative in REMOTE_PATHS.items():
            shutil.copy2(repo / relative, stage / name)
        bundle = _write_manifest(stage, BUNDLED_REVISION, "Native 0.2.4")
        if destination.exists():
            if not destination.is_dir():
                raise PatcherError(f"Путь пакета занят файлом: {destination}")
            previous = destination.with_name(f".{destination.name}-previous-{uuid.uuid4().hex}")
            os.replace(destination, previous)
        try:
            os.replace(stage, destination)
        except OSError:
            if previous is not None and previous.exists() and not destination.exists():
                os.replace(previous, destination)
                previous = None
            raise
        if previous is not None:
            shutil.rmtree(previous, ignore_errors=True)
            previous = None
        return Bundle(destination, bundle.revision, bundle.label, bundle.files)
    except PatcherError:
        raise
    except OSError as exc:
        raise PatcherError(f"Не удалось создать встроенный пакет: {exc}") from exc
    finally:
        if stage.exists():
            shutil.rmtree(stage, ignore_errors=True)
        if previous is not None and previous.exists() and not destination.exists():
            try:
                os.replace(previous, destination)
            except OSError:
                pass


def _cache_root(data_dir: Path) -> Path:
    return Path(data_dir) / "cache"


def latest_cached(data_dir: Path, bundled: Bundle) -> Bundle:
    """Return the published cached bundle, or the built-in bundle when offline."""
    validate_bundle(bundled)
    cache = _cache_root(data_dir)
    pointer = cache / "current.json"
    if pointer.exists():
        try:
            raw = json.loads(pointer.read_text(encoding="utf-8"))
            revision = raw["revision"]
        except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
            raise PatcherError("Указатель кэша обновлений повреждён.") from exc
        if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision):
            raise PatcherError("Указатель кэша содержит неверную ревизию.")
        candidate = load_bundle(cache / revision)
        validate_bundle(candidate)
        return candidate
    return bundled


def _open_with_retries(url: str):
    request = urllib.request.Request(url, headers={"User-Agent": "DLSSG-Patcher/1.0", "Accept": "application/vnd.github+json"})
    last_error: Exception | None = None
    for attempt in range(HTTP_RETRIES + 1):
        try:
            return urllib.request.urlopen(request, timeout=HTTP_TIMEOUT)
        except urllib.error.HTTPError as exc:
            last_error = exc
            if exc.code == 403:
                reset = exc.headers.get("X-RateLimit-Reset") if exc.headers else None
                detail = f" Лимит сбросится после {reset}." if reset else ""
                raise PatcherError(f"GitHub временно ограничил проверку обновлений.{detail}") from exc
            if exc.code < 500 or attempt == HTTP_RETRIES:
                break
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_error = exc
            if attempt == HTTP_RETRIES:
                break
        time.sleep(0.15 * (attempt + 1))
    raise PatcherError(f"Не удалось получить данные GitHub: {last_error}") from last_error


def _read_limited(response, limit: int, progress: Callable[[int, int | None], None] | None = None) -> bytes:
    length_header = response.headers.get("Content-Length") if getattr(response, "headers", None) else None
    expected = int(length_header) if length_header and length_header.isdigit() else None
    if expected is not None and expected > limit:
        raise PatcherError("GitHub вернул файл недопустимого размера.")
    data = bytearray()
    while True:
        chunk = response.read(min(1024 * 1024, limit + 1 - len(data)))
        if not chunk:
            break
        data.extend(chunk)
        if len(data) > limit:
            raise PatcherError("GitHub вернул файл недопустимого размера.")
        if progress:
            progress(len(data), expected)
    if expected is not None and len(data) != expected:
        raise PatcherError("Загрузка прервана: размер не совпадает с Content-Length.")
    return bytes(data)


def _fetch(url: str, limit: int, progress=None) -> bytes:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname not in {API_HOST, RAW_HOST}:
        raise PatcherError("Заблокирован недоверенный адрес обновления.")
    try:
        with _open_with_retries(url) as response:
            final_url = response.geturl() if hasattr(response, "geturl") else url
            final = urllib.parse.urlsplit(final_url)
            if final.scheme != "https" or final.hostname != parsed.hostname:
                raise PatcherError("GitHub перенаправил загрузку на недоверенный адрес.")
            return _read_limited(response, limit, progress)
    except PatcherError:
        raise
    except (ValueError, OSError, urllib.error.URLError) as exc:
        raise PatcherError(f"Загрузка обновления прервана: {exc}") from exc


def _fetch_json(url: str) -> object:
    try:
        return json.loads(_fetch(url, 4 * 1024 * 1024).decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise PatcherError("GitHub вернул повреждённый JSON.") from exc


def _tree_blobs(revision: str) -> dict[str, str]:
    tree_url = f"https://{API_HOST}/repos/{UPSTREAM}/git/trees/{revision}?recursive=1"
    raw = _fetch_json(tree_url)
    if not isinstance(raw, dict) or raw.get("truncated") or not isinstance(raw.get("tree"), list):
        raise PatcherError("GitHub не вернул полное дерево выбранной ревизии.")
    allowed = {*REMOTE_PATHS.values(), README_PATH}
    blobs: dict[str, str] = {}
    for item in raw["tree"]:
        if not isinstance(item, dict) or item.get("path") not in allowed:
            continue
        if item.get("type") != "blob" or not re.fullmatch(r"[0-9a-f]{40}", str(item.get("sha", ""))):
            raise PatcherError(f"Некорректная запись Git для {item.get('path')}.")
        blobs[item["path"]] = item["sha"]
    if set(blobs) != allowed:
        raise PatcherError("В выбранной ревизии GitHub отсутствуют обязательные файлы.")
    return blobs


def _label_from_readme(data: bytes, revision: str) -> str:
    text = data.decode("utf-8", errors="replace")
    match = re.search(r"Native\s+v?(\d+(?:\.\d+){1,3})", text, re.IGNORECASE)
    return f"Native {match.group(1)}" if match else f"GitHub {revision[:8]}"


def _notify(progress, message: str) -> None:
    if progress is None:
        return
    try:
        progress(message)
    except TypeError:
        pass


def check_for_update(data_dir: Path, current: Bundle, progress=None) -> Bundle:
    """Fetch, verify and atomically publish one immutable upstream revision."""
    validate_bundle(current)
    _notify(progress, "Проверка GitHub…")
    commit_url = f"https://{API_HOST}/repos/{UPSTREAM}/commits/main"
    commit = _fetch_json(commit_url)
    revision = commit.get("sha") if isinstance(commit, dict) else None
    if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise PatcherError("GitHub вернул неверную ревизию main.")
    if revision == current.revision:
        return current

    blobs = _tree_blobs(revision)
    cache = _cache_root(data_dir)
    cache.mkdir(parents=True, exist_ok=True)
    final = cache / revision
    if final.exists():
        cached = load_bundle(final)
        validate_bundle(cached)
        _publish_pointer(cache, revision)
        return cached

    stage = Path(tempfile.mkdtemp(prefix=".download-", dir=cache))
    total = 0
    try:
        for name, remote_path in (*REMOTE_PATHS.items(), (README_PATH, README_PATH)):
            _notify(progress, f"Загрузка {name}…")
            url = f"https://{RAW_HOST}/{UPSTREAM}/{revision}/{remote_path}"
            data = _fetch(url, MAX_FILE_SIZE)
            total += len(data)
            if total > MAX_TOTAL_SIZE:
                raise PatcherError("Общий размер обновления превышает допустимый предел.")
            if _git_blob_sha1(data) != blobs[remote_path]:
                raise PatcherError(f"{name}: Git blob SHA-1 не совпадает с деревом ревизии.")
            (stage / name).write_bytes(data)

        label = _label_from_readme((stage / README_PATH).read_bytes(), revision)
        (stage / README_PATH).unlink()
        candidate = _write_manifest(stage, revision, label)
        if candidate.files == current.files:
            return current
        os.replace(stage, final)
        published = Bundle(final, candidate.revision, candidate.label, candidate.files)
        _publish_pointer(cache, revision)
        return published
    except PatcherError:
        raise
    except OSError as exc:
        raise PatcherError(f"Не удалось сохранить обновление: {exc}") from exc
    finally:
        if stage.exists():
            shutil.rmtree(stage, ignore_errors=True)


def _publish_pointer(cache: Path, revision: str) -> None:
    temp = cache / f".current-{uuid.uuid4().hex}.json"
    try:
        temp.write_text(json.dumps({"revision": revision}) + "\n", encoding="utf-8")
        os.replace(temp, cache / "current.json")
    except OSError as exc:
        raise PatcherError(f"Не удалось опубликовать обновление: {exc}") from exc
    finally:
        temp.unlink(missing_ok=True)
