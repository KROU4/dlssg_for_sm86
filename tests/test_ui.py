from __future__ import annotations

import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QMessageBox

from patcher_app import ui
from patcher_app.models import Bundle, Game, PatcherError


def _result(state: str = "absent", *, revision: str | None = None) -> dict:
    installed = state != "absent"
    return {
        "state": state,
        "message": state,
        "installed": installed,
        "revision": revision,
        "proxy": "version.dll" if installed else None,
        "can_install": not installed,
        "available_proxies": ["version.dll"],
        "settings": {
            "hardware_bilinear": 0,
            "diagnostics": True,
            "max_generated_frames": 3,
        },
    }


class FakeInstaller:
    instances: list["FakeInstaller"] = []

    def __init__(self, data_dir: Path):
        self.data_dir = Path(data_dir)
        self.current = _result()
        self.calls: list[tuple[str, Game, dict]] = []
        type(self).instances.append(self)

    def inspect(self, game: Game, bundle: Bundle) -> dict:
        self.calls.append(("inspect", game, {}))
        return dict(self.current)

    def install(self, game: Game, **kwargs) -> dict:
        self.calls.append(("install", game, kwargs))
        self.current = _result("installed", revision=kwargs["bundle"].revision)
        return dict(self.current)

    def check(self, game: Game, **kwargs) -> dict:
        self.calls.append(("check", game, kwargs))
        return dict(self.current)

    def rollback(self, game: Game, **kwargs) -> dict:
        self.calls.append(("rollback", game, kwargs))
        return dict(self.current)

    def uninstall(self, game: Game, **kwargs) -> dict:
        self.calls.append(("uninstall", game, kwargs))
        self.current = _result()
        return dict(self.current)

    def configure(self, game: Game, **kwargs) -> dict:
        self.calls.append(("configure", game, kwargs))
        return dict(self.current)

    def record_visual_confirmation(self, game: Game, **kwargs) -> dict:
        self.calls.append(("record_visual_confirmation", game, kwargs))
        self.current = _result("verified" if kwargs["ok"] else "failed", revision="old-revision")
        return dict(self.current)


class FakeConfirmationBox:
    ButtonRole = QMessageBox.ButtonRole
    choice = "cancel"

    def __init__(self, parent=None):
        self.buttons: dict[str, object] = {}

    def setWindowTitle(self, text):
        pass

    def setText(self, text):
        pass

    def setInformativeText(self, text):
        pass

    def addButton(self, text, role):
        button = object()
        if text.startswith("Да"):
            self.buttons["good"] = button
        elif text.startswith("Есть"):
            self.buttons["bad"] = button
        else:
            self.buttons["cancel"] = button
        return button

    def exec(self):
        return 0

    def clickedButton(self):
        return self.buttons[self.choice]


class MainWindowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.bundle = Bundle(self.root, "new-revision", "Native test")
        self.launcher = Path("G:/SteamLibrary/steamapps/common/Bodycam/Bodycam.exe")
        self.shipping = Path(
            "G:/SteamLibrary/steamapps/common/Bodycam/Bodycam/Binaries/Win64/Bodycam-Win64-Shipping.exe"
        )
        self.game = Game(
            exe=self.shipping,
            name="Bodycam",
            app_id="2406770",
            build_id="25228199",
            install_root=self.launcher.parent,
        )
        FakeInstaller.instances.clear()
        self.installer_patch = mock.patch.object(ui, "Installer", FakeInstaller)
        self.installer_patch.start()
        self.game_patch = mock.patch.object(ui.environment, "game_for_exe", side_effect=self._resolve_game)
        self.game_patch.start()
        self.windows: list[ui.MainWindow] = []

    def tearDown(self) -> None:
        for window in self.windows:
            window.pool.waitForDone(2000)
            QApplication.processEvents()
            window.close()
        self.game_patch.stop()
        self.installer_patch.stop()
        self.temp.cleanup()

    def _resolve_game(self, path: Path) -> Game:
        path = Path(path)
        if path == self.launcher or path == self.shipping:
            return self.game
        return Game(path, path.stem, install_root=path.parent)

    def _window(self) -> ui.MainWindow:
        window = ui.MainWindow(self.bundle, self.root / "data", auto_start=False, auto_updates=False)
        self.windows.append(window)
        return window

    def _wait_idle(self, window: ui.MainWindow, timeout_ms: int = 3000) -> None:
        deadline = time.monotonic() + timeout_ms / 1000
        while window._busy and time.monotonic() < deadline:
            QApplication.processEvents()
            QTest.qWait(10)
        QApplication.processEvents()
        self.assertFalse(window._busy, "background UI task did not finish")

    def test_initialize_selects_bodycam_rendering_exe(self) -> None:
        window = self._window()
        discovered = Game(
            self.launcher,
            "Bodycam",
            "2406770",
            "25228199",
            self.launcher.parent,
        )
        with mock.patch.object(ui.environment, "discover_steam_games", return_value=[discovered]), mock.patch.object(
            ui.environment,
            "gpu_info",
            return_value={"name": "RTX 3060 Ti", "memory_mib": 8192, "driver": "610.88", "compute_cap": "8.6"},
        ):
            window.initialize()
            self._wait_idle(window)
        self.assertEqual(window.game.exe, self.shipping)
        self.assertEqual(window.path_edit.text(), str(self.shipping))
        self.assertEqual(window.games_combo.currentData().app_id, "2406770")
        self.assertIn("экспериментальный", window.game_note.text())

    def test_no_game_disables_all_game_actions(self) -> None:
        window = self._window()
        controls = (
            window.install_button,
            window.update_button,
            window.check_button,
            window.rollback_button,
            window.uninstall_button,
            window.settings_button,
            window.launch_button,
            window.confirm_button,
            window.logs_button,
        )
        self.assertTrue(all(not control.isEnabled() for control in controls))
        self.assertTrue(window.fetch_button.isEnabled())
        self.assertTrue(window.exe_button.isEnabled())

    def test_installed_old_revision_enables_update_and_management(self) -> None:
        window = self._window()
        window.game = self.game
        window._display_result(_result("installed", revision="old-revision"))
        self.assertFalse(window.install_button.isEnabled())
        self.assertTrue(window.update_button.isEnabled())
        self.assertTrue(window.rollback_button.isEnabled())
        self.assertTrue(window.uninstall_button.isEnabled())
        self.assertTrue(window.settings_button.isEnabled())
        self.assertFalse(window.confirm_button.isEnabled())

    def test_network_failure_keeps_bundle_and_reenables_ui(self) -> None:
        window = self._window()
        window.game = self.game
        window._display_result(_result())
        original = window.bundle
        with mock.patch.object(ui.packages, "check_for_update", side_effect=PatcherError("сеть недоступна")):
            window.fetch_updates()
            self._wait_idle(window)
        self.assertIs(window.bundle, original)
        self.assertTrue(window.fetch_button.isEnabled())
        self.assertTrue(window.install_button.isEnabled())
        self.assertIn("сеть недоступна", window.footer.text())

    def test_operation_result_preserves_selected_game(self) -> None:
        window = self._window()
        window._set_game(self.game)
        selected_text = window.path_edit.text()
        window._install()
        self._wait_idle(window)
        self.assertEqual(window.game, self.game)
        self.assertEqual(window.path_edit.text(), selected_text)
        self.assertEqual(window.result["state"], "installed")
        self.assertTrue(any(call[0] == "install" and call[1] == self.game for call in window.installer.calls))

    def test_only_explicit_positive_visual_confirmation_reaches_verified(self) -> None:
        window = self._window()
        window.game = self.game
        window.installer.current = _result("loaded", revision="old-revision")
        window._display_result(window.installer.current)
        self.assertEqual(window.result["state"], "loaded")

        FakeConfirmationBox.choice = "cancel"
        with mock.patch.object(ui, "QMessageBox", FakeConfirmationBox):
            window._confirm_visual()
        self.assertFalse(any(call[0] == "record_visual_confirmation" for call in window.installer.calls))
        self.assertEqual(window.result["state"], "loaded")

        FakeConfirmationBox.choice = "good"
        with mock.patch.object(ui, "QMessageBox", FakeConfirmationBox):
            window._confirm_visual()
            self._wait_idle(window)
        confirmations = [call for call in window.installer.calls if call[0] == "record_visual_confirmation"]
        self.assertEqual(len(confirmations), 1)
        self.assertTrue(confirmations[0][2]["ok"])
        self.assertEqual(window.result["state"], "verified")


if __name__ == "__main__":
    unittest.main()
