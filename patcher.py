"""GUI entry point and a small, scriptable verification interface."""
from __future__ import annotations

import argparse
import ctypes
import json
import os
from pathlib import Path
import sys
import traceback


def application_root() -> Path:
    return Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parent


def protect_dll_search() -> dict:
    """Qt and extension modules must not search the project's proxy directory."""
    info = {"pid": os.getpid(), "frozen": bool(getattr(sys, "frozen", False)), "version_dll": None}
    if sys.platform != "win32":
        return info
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
    kernel.GetModuleHandleW.restype = ctypes.c_void_p
    kernel.GetModuleFileNameW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint]
    kernel.GetSystemDirectoryW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint]
    system = ctypes.create_unicode_buffer(32768)
    if not kernel.GetSystemDirectoryW(system, len(system)):
        raise RuntimeError("Не удалось определить каталог Windows System32.")
    for name in ("version.dll", "dxgi.dll", "winmm.dll", "winhttp.dll", "dinput8.dll"):
        version = kernel.GetModuleHandleW(name)
        if not version:
            continue
        buffer = ctypes.create_unicode_buffer(32768)
        if not kernel.GetModuleFileNameW(version, buffer, len(buffer)):
            raise RuntimeError("Не удалось проверить системную version.dll.")
        if name == "version.dll":
            info["version_dll"] = buffer.value
        if Path(buffer.value).resolve().parent != Path(system.value).resolve():
            raise RuntimeError(f"В патчер загружена несистемная {name}. Игра не изменена. Нужна проверка сборки приложения.")
    kernel.SetDefaultDllDirectories.argtypes = [ctypes.c_uint]
    kernel.SetDefaultDllDirectories.restype = ctypes.c_int
    if not kernel.SetDefaultDllDirectories(0x00000800 | 0x00000400):
        raise RuntimeError("Не удалось изолировать поиск DLL патчера.")
    if getattr(sys, "frozen", False):
        kernel.AddDllDirectory.argtypes = [ctypes.c_wchar_p]
        kernel.AddDllDirectory.restype = ctypes.c_void_p
        # Keep the cookie alive for the process lifetime.
        info["dll_directory_cookie"] = kernel.AddDllDirectory(str(Path(sys._MEIPASS)))
        if not info["dll_directory_cookie"]:
            raise RuntimeError("Не удалось подключить встроенные библиотеки патчера.")
    return info


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="DLSSG Patcher")
    result.add_argument("--no-network", action="store_true")
    result.add_argument("--self-test", action="store_true", help="Open/render GUI, inspect environment and exit without changing any game")
    result.add_argument("--report", type=Path)
    result.add_argument("--screenshot", type=Path)
    result.add_argument("--data-dir", type=Path)
    result.add_argument("--game", type=Path)
    result.add_argument("--action", choices=("inspect", "check", "install", "update", "rollback", "uninstall", "configure", "fetch"))
    result.add_argument("--diagnostics", choices=("on", "off"), default=None)
    result.add_argument("--max-generated-frames", type=int, choices=(1, 2, 3))
    return result


def write_report(path: Path | None, report: dict):
    text = json.dumps(report, ensure_ascii=False, indent=2, default=str)
    if path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    if sys.stdout is not None:
        print(text)


def main() -> int:
    if sys.stdout is not None and hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    args = parser().parse_args()
    try:
        safety = protect_dll_search()
        from patcher_app import packages, environment
        from patcher_app.installer import Installer
        from patcher_app.models import PatcherError
        root = application_root()
        data_dir = (args.data_dir or root / "patcher-data").resolve()
        if getattr(sys, "frozen", False):
            bundle = packages.load_bundle(Path(sys._MEIPASS) / "payload")
        else:
            bundle = packages.create_bundled_payload(root, root / "build" / "bundled-payload")
        packages.validate_bundle(bundle)
        startup_warning = None
        try:
            bundle = packages.latest_cached(data_dir, bundle)
        except (PatcherError, OSError, ValueError) as exc:
            startup_warning = f"Кэш не использован: {exc}. Доступен встроенный комплект."
        manager = Installer(data_dir)
        if args.action:
            if args.action == "fetch":
                if args.no_network:
                    raise PatcherError("Загрузка отключена параметром --no-network.")
                bundle = packages.check_for_update(data_dir, bundle)
                result = {"revision": bundle.revision, "label": bundle.label}
            else:
                if not args.game:
                    raise PatcherError("Для операции требуется --game с путём игрового EXE.")
                game = environment.game_for_exe(args.game)
                if args.action == "inspect":
                    result = manager.inspect(game, bundle)
                elif args.action in {"install", "update"}:
                    result = manager.install(game, bundle, diagnostics=args.diagnostics != "off")
                elif args.action == "configure":
                    result = manager.configure(game, diagnostics=None if args.diagnostics is None else args.diagnostics == "on", max_generated_frames=args.max_generated_frames)
                else:
                    result = getattr(manager, args.action)(game)
            succeeded = result.get("state") != "failed"
            write_report(args.report, {"ok": succeeded, "action": args.action, "result": result, "runtime": safety})
            return 0 if succeeded else 1

        from PySide6.QtCore import QTimer
        from PySide6.QtWidgets import QApplication
        from patcher_app.ui import MainWindow
        app = QApplication(sys.argv[:1])
        protect_dll_search()
        app.setApplicationName("DLSSG Patcher")
        app.setOrganizationName("DLSSG Patcher")
        window = MainWindow(bundle, data_dir, auto_start=not args.self_test, auto_updates=not args.no_network)
        if startup_warning:
            window.log(startup_warning)
        window.show()
        if args.self_test:
            def finish_test():
                try:
                    games = environment.discover_steam_games()
                    gpu = environment.gpu_info()
                    window.gpu_label.setText(gpu.get("name", "Не определена"))
                    window.gpu_detail.setText(f"{gpu.get('memory_mib', '?')} МиБ VRAM · драйвер {gpu.get('driver', '?')} · SM {gpu.get('compute_cap', '?')}")
                    game = environment.game_for_exe(args.game) if args.game else next((g for g in games if g.app_id == "2406770"), None)
                    if game:
                        window.games_combo.addItem(game.name, game)
                        window.games_combo.setCurrentIndex(window.games_combo.count() - 1)
                        window._set_game(game)
                    window.log("Самопроверка: интерфейс открыт; файлы игр не изменялись.")
                    app.processEvents()
                    if args.screenshot:
                        args.screenshot.parent.mkdir(parents=True, exist_ok=True)
                        if not window.grab().save(str(args.screenshot)):
                            raise RuntimeError("Не удалось сохранить снимок интерфейса.")
                    runtime = protect_dll_search()
                    modules = environment.loaded_modules(os.getpid())
                    proxy_modules = [p for p in modules if Path(p).name.lower() in {"version.dll", "dxgi.dll", "winmm.dll", "winhttp.dll", "dinput8.dll"}]
                    write_report(args.report, {"ok": True, "runtime": runtime, "proxy_named_modules": proxy_modules, "gpu": gpu, "bundle": {"revision": bundle.revision, "label": bundle.label}, "game": str(game.exe) if game else None, "inspection": window.result, "gui_size": [window.width(), window.height()], "screenshot": args.screenshot})
                    app.exit(0)
                except Exception as exc:
                    write_report(args.report, {"ok": False, "error": str(exc), "traceback": traceback.format_exc()})
                    app.exit(1)
            QTimer.singleShot(250, finish_test)
        return app.exec()
    except Exception as exc:
        write_report(args.report, {"ok": False, "error": str(exc), "traceback": traceback.format_exc()})
        if not args.action and not args.self_test and sys.platform == "win32":
            ctypes.windll.user32.MessageBoxW(None, str(exc), "DLSSG Patcher — ошибка запуска", 0x10)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
