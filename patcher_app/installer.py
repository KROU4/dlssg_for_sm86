from __future__ import annotations

import hashlib
import json
import os
import shutil
import time
import uuid
import ctypes
import re
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator

from .models import Bundle, Game, INI_NAME, PROXY_NAMES, PatcherError


_MANAGED_INI_KEYS = {
    ("Compatibility", "Router"): "SM86",
    ("Compatibility", "KernelImage"): "PTX",
    ("Compatibility", "HardwareBilinear"): "0",
    ("FrameGeneration", "MaxGeneratedFrames"): "3",
    ("Logging", "Level"): "2",
}
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _base_result(**values: Any) -> dict[str, Any]:
    result = {"state": "absent", "message": "Патч не установлен", "proxy": None,
              "revision": None, "installed": False}
    result.update(values)
    return result


class Installer:
    """Transactional installer for one proxy DLL and its INI configuration."""

    def __init__(self, data_dir: Path, process_checker: Callable[[Game], Any] | None = None):
        self.data_dir = Path(data_dir)
        self.process_checker = process_checker
        for name in ("installations", "backups", "journals", "locks"):
            (self.data_dir / name).mkdir(parents=True, exist_ok=True)

    def inspect(self, game: Game, bundle: Bundle | None = None) -> dict[str, Any]:
        try:
            return self._inspect_impl(game, bundle)
        except Exception as exc:
            result = self._failure(exc)
            result.update(can_install=False, conflicts=[], available_proxies=[],
                          settings=self._read_settings(game.directory / INI_NAME))
            return result

    def _inspect_impl(self, game: Game, bundle: Bundle | None = None) -> dict[str, Any]:
        record = self._load_record(game)
        env = self._environment()
        exe_info = env.inspect_exe(game.exe)
        imports = {str(item).lower() for item in (
            list(exe_info.get("imports", [])) + list(exe_info.get("delay_imports", []))
        )}
        occupied = [name for name in PROXY_NAMES if (game.directory / name).exists()]
        owned = set(record.get("files", {})) if record else set()
        conflicts = [name for name in occupied if name not in owned]
        available = [name for name in PROXY_NAMES if name in imports and name not in conflicts]
        anti_cheat = env.detect_anticheat(game)

        result = self._status_from_record(game, record)
        result.update({
            "can_install": bool(game.exe.is_file() and available and not anti_cheat),
            "conflicts": conflicts,
            "available_proxies": available,
            "anti_cheat": anti_cheat,
            "machine": exe_info.get("machine"),
            "settings": self._read_settings(game.directory / INI_NAME),
        })
        if bundle is not None:
            try:
                self._packages().validate_bundle(bundle)
                result["bundle_valid"] = True
            except Exception as exc:
                result["bundle_valid"] = False
                result["can_install"] = False
                result["message"] = f"Комплект повреждён: {exc}"
        return result

    def install(self, game: Game, bundle: Bundle, proxy: str | None = None,
                diagnostics: bool = True) -> dict[str, Any]:
        try:
            self._ensure_game_closed(game)
            with self._game_lock(game):
                self._recover(game)
                self._packages().validate_bundle(bundle)
                info = self._inspect_impl(game, bundle)
                if info.get("anti_cheat"):
                    raise PatcherError("Обнаружена защита игры; автоматическая установка остановлена")
                if info.get("machine") not in (None, 0x8664, "x64", "amd64", "AMD64"):
                    raise PatcherError("Поддерживаются только 64-битные игры")

                previous = self._load_record(game)
                self._assert_owned_unmodified(game, previous)
                known_hashes = {value for name, value in bundle.files.items() if name in PROXY_NAMES}
                owned_names = set(previous.get("files", {})) if previous else set()
                unmanaged_project = []
                for name in PROXY_NAMES:
                    candidate = game.directory / name
                    if candidate.is_file() and name not in owned_names:
                        try:
                            if (_sha256(candidate) in known_hashes
                                    or self._looks_like_dlssg_proxy(candidate)):
                                unmanaged_project.append(name)
                        except OSError:
                            pass
                if unmanaged_project:
                    raise PatcherError(
                        "Мод уже установлен другой копией патчера, но резервная запись недоступна: "
                        + ", ".join(unmanaged_project))
                chosen = self._choose_proxy(game, info, previous, proxy)
                ini_source = bundle.root / INI_NAME
                proxy_source = bundle.root / chosen
                if not ini_source.is_file() or not proxy_source.is_file():
                    raise PatcherError("В комплекте отсутствуют необходимые файлы")

                if (previous and previous.get("revision") == bundle.revision
                        and previous.get("proxy") == chosen
                        and previous.get("files", {}).get(chosen) == _sha256(proxy_source)):
                    return self._status_from_record(game, previous, "Этот комплект уже установлен")

                ini_changes = {}
                if not previous:
                    ini_changes[("Logging", "Level")] = "2" if diagnostics else "1"
                ini_text = self._merge_ini(game.directory / INI_NAME, ini_source, ini_changes)
                writes = {chosen: proxy_source.read_bytes(), INI_NAME: ini_text.encode("utf-8")}
                remove = []
                if previous and previous.get("proxy") != chosen:
                    remove.append(previous["proxy"])
                record = self._apply_operation(game, "install", writes, remove, previous)
                now = time.time()
                record.update({
                    "game": self._game_dict(game), "proxy": chosen, "revision": bundle.revision,
                    "label": bundle.label, "installed_at": now, "evidence_after": now,
                    "log_baseline": self._capture_log_baseline(game),
                    "files": {name: _sha256(game.directory / name) for name in writes},
                    "state": "installed", "loaded_evidence": None, "visual_confirmation": None,
                })
                self._save_record(game, record, finish_transaction=True)
                return self._status_from_record(game, record, "Файлы патча установлены")
        except Exception as exc:
            return self._failure_after_recovery(game, exc)

    def rollback(self, game: Game) -> dict[str, Any]:
        try:
            self._ensure_game_closed(game)
            with self._game_lock(game):
                self._recover(game)
                record = self._load_record(game)
                if not record or not record.get("history"):
                    raise PatcherError("Нет точки отката")
                self._assert_owned_unmodified(game, record)
                operation = record["history"][-1]
                previous = operation.get("record_before")
                if previous is not None:
                    previous = dict(previous)
                    previous["history"] = list(record["history"][:-1])
                self._transactional_restore(game, operation, record, previous)
                if previous:
                    return self._status_from_record(game, previous, "Предыдущее состояние восстановлено")
                return _base_result(message="Первоначальная установка отменена")
        except Exception as exc:
            return self._failure_after_recovery(game, exc)

    def uninstall(self, game: Game) -> dict[str, Any]:
        try:
            self._ensure_game_closed(game)
            with self._game_lock(game):
                self._recover(game)
                record = self._load_record(game)
                if not record:
                    return _base_result(message="Патч уже отсутствует")
                self._assert_owned_unmodified(game, record)
                first = record.get("history", [None])[0]
                if not first:
                    raise PatcherError("Не найдена резервная копия установки")
                current_proxy = record.get("proxy")
                extra_remove = [current_proxy] if current_proxy and current_proxy not in first.get("names", []) else []
                self._transactional_restore(game, first, record, None, extra_remove)
                return _base_result(message="Патч удалён, исходные файлы восстановлены")
        except Exception as exc:
            return self._failure_after_recovery(game, exc)

    def configure(self, game: Game, diagnostics: bool | None = None,
                  hardware_bilinear: bool | None = None,
                  max_generated_frames: int | None = None) -> dict[str, Any]:
        try:
            self._ensure_game_closed(game)
            with self._game_lock(game):
                self._recover(game)
                previous = self._load_record(game)
                if not previous:
                    raise PatcherError("Сначала установите патч")
                self._assert_owned_unmodified(game, previous)
                if max_generated_frames is not None and max_generated_frames not in (1, 2, 3):
                    raise PatcherError("MaxGeneratedFrames должен быть от 1 до 3")
                changes: dict[tuple[str, str], str] = {}
                if diagnostics is not None:
                    changes[("Logging", "Level")] = "2" if diagnostics else "1"
                if hardware_bilinear is not None:
                    changes[("Compatibility", "HardwareBilinear")] = "1" if hardware_bilinear else "0"
                if max_generated_frames is not None:
                    changes[("FrameGeneration", "MaxGeneratedFrames")] = str(max_generated_frames)
                ini_path = game.directory / INI_NAME
                text = self._merge_ini(ini_path, ini_path, changes)
                record = self._apply_operation(game, "configure", {INI_NAME: text.encode("utf-8")}, [], previous)
                record.update(previous)
                record["history"] = self._last_history
                record["files"] = dict(previous["files"])
                record["files"][INI_NAME] = _sha256(ini_path)
                record["evidence_after"] = time.time()
                record["log_baseline"] = self._capture_log_baseline(game)
                record["state"] = "installed"
                record["loaded_evidence"] = None
                record["visual_confirmation"] = None
                self._save_record(game, record, finish_transaction=True)
                return self._status_from_record(game, record, "Настройки сохранены")
        except Exception as exc:
            return self._failure_after_recovery(game, exc)

    def check(self, game: Game) -> dict[str, Any]:
        try:
            with self._game_lock(game):
                if self._journal_path(game).exists():
                    raise PatcherError("Найдена незавершённая операция; закройте игру и повторите изменение")
                return self._check_impl(game)
        except Exception as exc:
            return self._failure(exc)

    def _check_impl(self, game: Game) -> dict[str, Any]:
        record = self._load_record(game)
        result = self._status_from_record(game, record)
        result["settings"] = self._read_settings(game.directory / INI_NAME)
        if not record or result["state"] == "modified":
            return result
        if result["state"] == "stale":
            record["game"] = self._game_dict(game)
            record["state"] = "installed"
            record["evidence_after"] = time.time()
            record["log_baseline"] = self._capture_log_baseline(game)
            record["loaded_evidence"] = None
            record["visual_confirmation"] = None
            self._save_record(game, record)
            return self._status_from_record(game, record, "Новая сборка учтена; перезапустите игру и проверьте журнал")
        if "log_baseline" not in record:
            record["log_baseline"] = self._capture_log_baseline(game)
            record["evidence_after"] = time.time()
            record["state"] = "installed"
            record["loaded_evidence"] = None
            record["visual_confirmation"] = None
            self._save_record(game, record)
            return self._status_from_record(game, record, "Диагностика подготовлена; перезапустите игру")
        evidence = self._fresh_log_evidence(game, record.get("log_baseline", {}))
        if evidence.get("failure"):
            record["state"] = "failed"
            record["failure_evidence"] = evidence
            self._save_record(game, record)
            result.update(state="failed", message="Журнал сообщает об ошибке загрузки")
        elif evidence.get("loaded"):
            if not (record.get("visual_confirmation") or {}).get("ok"):
                record["loaded_evidence"] = evidence
                record["state"] = "loaded"
                self._save_record(game, record)
                result.update(state="loaded", message="Загрузка мода подтверждена журналом")
        return result

    def record_visual_confirmation(self, game: Game, ok: bool, notes: str = "") -> dict[str, Any]:
        try:
            with self._game_lock(game):
                if self._journal_path(game).exists():
                    raise PatcherError("Найдена незавершённая операция")
                record = self._load_record(game)
                if not record or not record.get("loaded_evidence"):
                    raise PatcherError("Сначала подтвердите загрузку свежим журналом")
                if self._status_from_record(game, record)["state"] in {"stale", "modified"}:
                    raise PatcherError("Игра или файлы изменились; проверку нужно повторить")
                record["visual_confirmation"] = {
                    "ok": bool(ok), "notes": notes, "at": time.time(),
                    "revision": record.get("revision"), "build_id": game.build_id,
                }
                record["state"] = "verified" if ok else "failed"
                self._save_record(game, record)
                return self._status_from_record(
                    game, record, "Генерация кадров подтверждена" if ok else "Визуальная проверка не пройдена")
        except Exception as exc:
            return self._failure(exc)

    def _status_from_record(self, game: Game, record: dict[str, Any] | None,
                            message: str | None = None) -> dict[str, Any]:
        if not record:
            return _base_result(message=message or "Патч не установлен")
        changed = self._modified_files(game, record)
        state = record.get("state", "installed")
        if changed:
            state, message = "modified", "Файлы патча изменены вне программы"
        elif record.get("game", {}).get("build_id") != game.build_id:
            state, message = "stale", "Игра обновилась; совместимость нужно проверить заново"
        elif game.build_id is None and record.get("game", {}).get("exe_identity") != self._exe_identity(game.exe):
            state, message = "stale", "Исполняемый файл игры изменился; проверку нужно повторить"
        return _base_result(state=state, message=message or "Патч установлен",
                            proxy=record.get("proxy"), revision=record.get("revision"),
                            installed=True, modified_files=changed)

    def _choose_proxy(self, game: Game, info: dict[str, Any], previous: dict[str, Any] | None,
                      requested: str | None) -> str:
        candidates = info["available_proxies"]
        if requested:
            requested = requested.lower()
            if requested not in PROXY_NAMES or requested not in candidates:
                raise PatcherError(f"Загрузчик {requested} занят или не импортируется игрой")
            return requested
        if previous and previous.get("proxy") in candidates:
            return previous["proxy"]
        if not candidates:
            raise PatcherError("Не найден свободный загрузчик DLL, импортируемый игрой")
        return candidates[0]

    def _apply_operation(self, game: Game, kind: str, writes: dict[str, bytes],
                         remove: list[str], previous: dict[str, Any] | None) -> dict[str, Any]:
        allowed = {*PROXY_NAMES, INI_NAME}
        if (any(not isinstance(name, str) or name not in allowed for name in [*writes, *remove])
                or any(not isinstance(content, bytes) for content in writes.values())):
            raise PatcherError("Операция содержит недопустимое имя или содержимое файла")
        operation_id = f"{int(time.time())}-{uuid.uuid4().hex[:8]}"
        backup = self.data_dir / "backups" / self._game_id(game) / operation_id
        backup.mkdir(parents=True, exist_ok=False)
        names = list(dict.fromkeys([*writes, *remove]))
        existing: list[str] = []
        for name in names:
            source = game.directory / name
            if source.exists():
                shutil.copy2(source, backup / name)
                existing.append(name)
        backup_hashes = {name: _sha256(backup / name) for name in existing}
        history_entry = {
            "id": operation_id, "kind": kind, "backup": str(backup), "names": names,
            "existing": existing, "backup_hashes": backup_hashes,
            "record_before": self._record_snapshot(previous),
        }
        journal = self._journal_path(game)
        self._write_json_atomic(journal, {"operation": history_entry, "previous_record": previous,
                                         "phase": "prepared"})
        try:
            for name, content in writes.items():
                self._write_bytes_atomic(game.directory / name, content)
            for name in remove:
                target = game.directory / name
                if target.exists():
                    target.unlink()
            history = list(previous.get("history", [])) if previous else []
            history.append(history_entry)
            self._last_history = history
            return {"history": history}
        except Exception:
            self._restore_snapshot(game, history_entry)
            journal.unlink(missing_ok=True)
            raise

    def _transactional_restore(self, game: Game, snapshot: dict[str, Any],
                               current: dict[str, Any], target_record: dict[str, Any] | None,
                               extra_remove: list[str] | None = None) -> None:
        writes, remove = self._snapshot_actions(game, snapshot)
        for name in extra_remove or []:
            if name not in writes and name not in remove:
                if name not in PROXY_NAMES:
                    raise PatcherError("Запись установки содержит недопустимое имя файла")
                remove.append(name)
        self._apply_operation(game, "restore", writes, remove, current)
        if target_record is None:
            self._delete_record(game)
            self._journal_path(game).unlink(missing_ok=True)
        else:
            self._save_record(game, target_record, finish_transaction=True)

    def _snapshot_actions(self, game: Game, operation: dict[str, Any]) -> tuple[dict[str, bytes], list[str]]:
        backup = self._validate_operation(game, operation)
        existing = set(operation["existing"])
        writes = {name: (backup / name).read_bytes() for name in existing}
        return writes, [name for name in operation["names"] if name not in existing]

    def _restore_snapshot(self, game: Game, operation: dict[str, Any]) -> None:
        backup = self._validate_operation(game, operation)
        existing = set(operation.get("existing", []))
        for name in operation.get("names", []):
            target = game.directory / name
            if name in existing:
                source = backup / name
                if not source.is_file():
                    raise PatcherError("Резервная копия повреждена")
                self._write_bytes_atomic(target, source.read_bytes())
            elif target.exists():
                target.unlink()

    def _validate_operation(self, game: Game, operation: dict[str, Any]) -> Path:
        names = operation.get("names")
        existing = operation.get("existing")
        hashes = operation.get("backup_hashes")
        allowed = {*PROXY_NAMES, INI_NAME}
        if (not isinstance(names, list) or len(names) != len(set(names))
                or any(not isinstance(name, str) or name not in allowed for name in names)
                or not isinstance(existing, list) or not set(existing).issubset(names)
                or not isinstance(hashes, dict) or set(hashes) != set(existing)):
            raise PatcherError("Журнал операции повреждён")
        backup_root = (self.data_dir / "backups" / self._game_id(game)).resolve()
        backup = Path(str(operation.get("backup", ""))).resolve()
        if not backup.is_relative_to(backup_root):
            raise PatcherError("Журнал содержит небезопасный путь резервной копии")
        for name in existing:
            path = backup / name
            if not path.is_file() or _sha256(path) != hashes[name]:
                raise PatcherError("Резервная копия повреждена")
        return backup

    def _recover(self, game: Game) -> None:
        journal = self._journal_path(game)
        if not journal.exists():
            return
        data = json.loads(journal.read_text(encoding="utf-8"))
        self._restore_snapshot(game, data["operation"])
        previous = data.get("previous_record")
        if previous is None:
            self._delete_record(game)
            journal.unlink(missing_ok=True)
        else:
            self._save_record(game, previous)
            journal.unlink(missing_ok=True)

    def _assert_owned_unmodified(self, game: Game, record: dict[str, Any] | None) -> None:
        if record:
            changed = self._modified_files(game, record)
            if changed:
                raise PatcherError("Операция отменена: установленные файлы изменены: " + ", ".join(changed))

    def _modified_files(self, game: Game, record: dict[str, Any]) -> list[str]:
        changed = []
        for name, expected in record.get("files", {}).items():
            path = game.directory / name
            try:
                actual = _sha256(path)
            except OSError:
                actual = None
            if actual != expected:
                changed.append(name)
        return changed

    def _merge_ini(self, current: Path, fallback: Path,
                   changes: dict[tuple[str, str], str]) -> str:
        source = current if current.is_file() else fallback
        if source.is_file():
            try:
                text = source.read_bytes().decode("utf-8-sig")
            except UnicodeDecodeError as exc:
                raise PatcherError(
                    f"{source.name} имеет неподдерживаемую кодировку; сохраните его как UTF-8") from exc
        else:
            text = ""
        lines = text.splitlines()
        desired = dict(changes)
        section: str | None = None
        seen: set[tuple[str, str]] = set()
        output: list[str] = []
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("[") and stripped.endswith("]"):
                section = stripped[1:-1]
            if section and "=" in line and not stripped.startswith((";", "#")):
                key = line.split("=", 1)[0].strip()
                managed = next((item for item in _MANAGED_INI_KEYS if item[0].lower() == section.lower()
                              and item[1].lower() == key.lower()), None)
                if managed:
                    seen.add(managed)
                match = next((item for item in desired if item[0].lower() == section.lower()
                              and item[1].lower() == key.lower()), None)
                if match:
                    output.append(f"{key}={desired[match]}")
                    continue
            output.append(line)
        missing: dict[str, list[tuple[str, str]]] = {}
        for (section_name, key), default_value in _MANAGED_INI_KEYS.items():
            if (section_name, key) not in seen:
                missing.setdefault(section_name, []).append((key, desired.get((section_name, key), default_value)))
        for section_name, pairs in missing.items():
            header_index = next((index for index, line in enumerate(output)
                                 if line.strip().casefold() == f"[{section_name}]".casefold()), None)
            additions = [f"{key}={value}" for key, value in pairs]
            if header_index is None:
                if output and output[-1] != "":
                    output.append("")
                output.extend([f"[{section_name}]", *additions])
            else:
                insert_at = next((index for index in range(header_index + 1, len(output))
                                  if output[index].strip().startswith("[")
                                  and output[index].strip().endswith("]")), len(output))
                output[insert_at:insert_at] = additions
        return "\n".join(output).rstrip() + "\n"

    @staticmethod
    def _read_settings(path: Path) -> dict[str, Any]:
        values: dict[tuple[str, str], str] = {}
        if path.is_file():
            section: str | None = None
            try:
                lines = path.read_text(encoding="utf-8-sig", errors="replace").splitlines()
            except OSError:
                lines = []
            for line in lines:
                stripped = line.strip()
                if stripped.startswith("[") and stripped.endswith("]"):
                    section = stripped[1:-1].lower()
                elif section and "=" in line and not stripped.startswith((";", "#")):
                    key, value = line.split("=", 1)
                    values[(section, key.strip().lower())] = value.strip()
        try:
            bilinear = int(values.get(("compatibility", "hardwarebilinear"), "0"))
        except ValueError:
            bilinear = 0
        try:
            frames = int(values.get(("framegeneration", "maxgeneratedframes"), "3"))
        except ValueError:
            frames = 3
        try:
            level = int(values.get(("logging", "level"), "1"))
        except ValueError:
            level = 1
        return {"hardware_bilinear": 1 if bilinear else 0,
                "max_generated_frames": frames if frames in (1, 2, 3) else 3,
                "diagnostics": level >= 2}

    @staticmethod
    def _looks_like_dlssg_proxy(path: Path) -> bool:
        """Recognize this class of NGX proxy independently of its revision/hash."""
        try:
            import pefile
        except ImportError:
            return False

        try:
            pe = pefile.PE(str(path), fast_load=True)
            try:
                pe.parse_data_directories(
                    directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
                exports = {
                    symbol.name.decode("ascii", errors="ignore")
                    for symbol in getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", [])
                    if symbol.name
                }
            finally:
                pe.close()
        except (OSError, TypeError, ValueError, pefile.PEFormatError):
            return False
        return {
            "NVSDK_NGX_D3D12_Init",
            "NVSDK_NGX_D3D12_EvaluateFeature",
        }.issubset(exports)

    def _capture_log_baseline(self, game: Game) -> dict[str, dict[str, int]]:
        result: dict[str, dict[str, int]] = {}
        log_dir = game.directory / "dlssg_sm86" / "logs"
        for path in log_dir.glob("*.jsonl") if log_dir.is_dir() else ():
            try:
                stat = path.stat()
                result[path.name] = {"size": stat.st_size, "mtime_ns": stat.st_mtime_ns,
                                     "ctime_ns": stat.st_ctime_ns, "inode": stat.st_ino,
                                     "device": stat.st_dev}
            except (OSError, UnicodeDecodeError):
                continue
        return result

    def _fresh_log_evidence(self, game: Game, baseline: dict[str, Any]) -> dict[str, Any]:
        failure = False
        loaded = False
        files: list[str] = []
        log_dir = game.directory / "dlssg_sm86" / "logs"
        for path in log_dir.glob("*.jsonl") if log_dir.is_dir() else ():
            try:
                stat = path.stat()
                prior = baseline.get(path.name) if isinstance(baseline, dict) else None
                start = 0
                if isinstance(prior, dict):
                    same_file = (prior.get("inode") == stat.st_ino
                                 and prior.get("device") == stat.st_dev
                                 and prior.get("ctime_ns", stat.st_ctime_ns) == stat.st_ctime_ns)
                    if same_file and stat.st_size >= int(prior.get("size", 0)):
                        start = int(prior.get("size", 0))
                    elif stat.st_mtime_ns <= int(prior.get("mtime_ns", 0)):
                        continue
                files.append(str(path))
                with path.open("rb") as stream:
                    stream.seek(start)
                    fresh = stream.read().decode("utf-8")
                events_by_pid: dict[int, dict[str, bool]] = {}
                for line in fresh.splitlines():
                    try:
                        event = json.loads(line)
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        continue
                    if not isinstance(event, dict):
                        continue
                    marker = str(event.get("event") or event.get("name") or "").lower()
                    pid = event.get("pid")
                    if isinstance(pid, int) and pid > 0:
                        proof = events_by_pid.setdefault(pid, {"configuration": False, "connected": False})
                        if (marker == "configuration" and event.get("runtime") == "native_pipeline"
                                and event.get("router") in (86, "86", "SM86")):
                            proof["configuration"] = True
                        if marker == "ngx_driver_connected":
                            proof["connected"] = True
                    if marker in {"configuration_error", "install_failed", "error", "fatal"}:
                        failure = True
                if any(proof["configuration"] and proof["connected"] for proof in events_by_pid.values()):
                    loaded = True
            except (OSError, UnicodeDecodeError):
                continue
        result = {"loaded": loaded, "failure": failure, "files": files, "checked_at": time.time()}
        if loaded:
            result["proof"] = "native_pipeline+ngx_driver_connected"
        return result

    def _ensure_game_closed(self, game: Game) -> None:
        if self.process_checker is not None:
            result = self.process_checker(game)
            if result is False:
                raise PatcherError("Закройте игру перед изменением файлов")
            return
        self._environment().ensure_game_closed(game)

    @contextmanager
    def _game_lock(self, game: Game) -> Iterator[None]:
        path = self.data_dir / "locks" / f"{self._game_id(game)}.lock"
        for attempt in range(2):
            try:
                descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                try:
                    os.write(descriptor, str(os.getpid()).encode("ascii"))
                finally:
                    os.close(descriptor)
                break
            except FileExistsError as exc:
                if attempt == 0 and self._remove_stale_lock(path):
                    continue
                raise PatcherError("Для этой игры уже выполняется другая операция") from exc
        try:
            yield
        finally:
            path.unlink(missing_ok=True)

    @staticmethod
    def _remove_stale_lock(path: Path) -> bool:
        try:
            pid = int(path.read_text(encoding="ascii").strip())
            if pid <= 0:
                return False
            if os.name == "nt":
                kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
                kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
                kernel32.OpenProcess.restype = ctypes.c_void_p
                kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
                kernel32.CloseHandle.restype = ctypes.c_int
                handle = kernel32.OpenProcess(0x1000, False, pid)
                if handle:
                    kernel32.CloseHandle(handle)
                    return False
                if ctypes.get_last_error() != 87:
                    return False
            else:
                os.kill(pid, 0)
                return False
        except ProcessLookupError:
            pass
        except (OSError, ValueError):
            return False
        path.unlink(missing_ok=True)
        return True

    def _load_record(self, game: Game) -> dict[str, Any] | None:
        path = self._record_path(game)
        if not path.is_file():
            return None
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise PatcherError("Запись установки повреждена") from exc
        self._validate_record(game, record)
        return record

    def _validate_record(self, game: Game, record: Any) -> None:
        if not isinstance(record, dict):
            raise PatcherError("Запись установки повреждена")
        proxy = record.get("proxy")
        files = record.get("files")
        revision = record.get("revision")
        game_data = record.get("game")
        if (proxy not in PROXY_NAMES or not isinstance(revision, str) or not revision
                or not isinstance(files, dict) or set(files) != {proxy, INI_NAME}
                or any(not isinstance(value, str) or not _HASH_RE.fullmatch(value) for value in files.values())
                or not isinstance(game_data, dict) or not isinstance(game_data.get("exe"), str)
                or os.path.normcase(os.path.abspath(game_data["exe"]))
                != os.path.normcase(os.path.abspath(str(game.exe)))):
            raise PatcherError("Запись установки имеет небезопасную или неполную структуру")
        history = record.get("history")
        if not isinstance(history, list) or len(history) > 256:
            raise PatcherError("История установки повреждена")
        for operation in history:
            self._validate_operation(game, operation)
            before = operation.get("record_before")
            if before is not None:
                if not isinstance(before, dict):
                    raise PatcherError("История установки повреждена")
                before_copy = dict(before)
                before_copy["history"] = []
                self._validate_record(game, before_copy)

    def _save_record(self, game: Game, record: dict[str, Any], finish_transaction: bool = False) -> None:
        self._write_json_atomic(self._record_path(game), record)
        if finish_transaction:
            self._journal_path(game).unlink(missing_ok=True)

    def _delete_record(self, game: Game) -> None:
        self._record_path(game).unlink(missing_ok=True)

    @staticmethod
    def _record_snapshot(record: dict[str, Any] | None) -> dict[str, Any] | None:
        if record is None:
            return None
        return {key: value for key, value in record.items() if key != "history"}

    @staticmethod
    def _write_bytes_atomic(path: Path, content: bytes) -> None:
        temp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
        try:
            with temp.open("wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp, path)
        finally:
            temp.unlink(missing_ok=True)

    def _write_json_atomic(self, path: Path, value: Any) -> None:
        self._write_bytes_atomic(path, json.dumps(value, ensure_ascii=False, indent=2).encode("utf-8"))

    def _game_id(self, game: Game) -> str:
        normalized = os.path.normcase(str(game.exe.resolve()))
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:24]

    def _record_path(self, game: Game) -> Path:
        return self.data_dir / "installations" / f"{self._game_id(game)}.json"

    def _journal_path(self, game: Game) -> Path:
        return self.data_dir / "journals" / f"{self._game_id(game)}.json"

    @staticmethod
    def _exe_identity(path: Path) -> dict[str, Any]:
        try:
            stat = path.stat()
            return {"size": stat.st_size, "mtime_ns": stat.st_mtime_ns, "sha256": _sha256(path)}
        except OSError as exc:
            raise PatcherError(f"Не удалось проверить EXE игры: {exc}") from exc

    @classmethod
    def _game_dict(cls, game: Game) -> dict[str, Any]:
        return {"exe": str(game.exe), "name": game.name, "app_id": game.app_id,
                "build_id": game.build_id, "install_root": str(game.install_root) if game.install_root else None,
                "exe_identity": cls._exe_identity(game.exe)}

    @staticmethod
    def _environment():
        from . import environment
        return environment

    @staticmethod
    def _packages():
        from . import packages
        return packages

    @staticmethod
    def _failure(exc: Exception) -> dict[str, Any]:
        return _base_result(state="failed", message=str(exc) or exc.__class__.__name__)

    def _failure_after_recovery(self, game: Game, exc: Exception) -> dict[str, Any]:
        try:
            if self._journal_path(game).exists():
                try:
                    self._ensure_game_closed(game)
                except Exception:
                    return self._failure(exc)
                with self._game_lock(game):
                    if self._journal_path(game).exists():
                        self._recover(game)
        except Exception as recovery_exc:
            return self._failure(PatcherError(f"{exc}; аварийное восстановление не удалось: {recovery_exc}"))
        return self._failure(exc)
