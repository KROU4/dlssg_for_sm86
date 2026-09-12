"""Russian desktop interface. File operations are delegated to Installer."""
from __future__ import annotations

import ctypes
import os
import sys
from pathlib import Path
from typing import Callable

from PySide6.QtCore import QObject, QRunnable, QThreadPool, QTimer, Signal, Qt
from PySide6.QtGui import QCloseEvent, QDesktopServices, QFont
from PySide6.QtCore import QUrl
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QFileDialog, QFrame, QGridLayout,
    QHBoxLayout, QLabel, QLineEdit, QMainWindow, QMessageBox, QPushButton,
    QPlainTextEdit, QVBoxLayout, QWidget,
)

from . import __version__
from . import environment, packages
from .installer import Installer
from .models import Bundle, Game, PatcherError


STYLE = """
QMainWindow, QWidget { background: #11151b; color: #e8edf5; font-family: 'Segoe UI'; font-size: 13px; }
QFrame#card { background: #1a202a; border: 1px solid #2a3442; border-radius: 12px; }
QFrame#card QLabel, QFrame#card QCheckBox { background: transparent; border: none; }
QLabel#title { font-size: 27px; font-weight: 700; }
QLabel#subtitle, QLabel#muted { color: #a9b7c9; }
QLabel#eyebrow { color: #6ce0b5; font-size: 11px; font-weight: 700; }
QLabel#value { font-size: 17px; font-weight: 600; }
QLabel#state { font-size: 20px; font-weight: 600; }
QLabel#step { padding: 7px 10px; background: #252e3b; border-radius: 6px; color: #a9b7c9; }
QLabel#warning { color: #edc983; background: transparent; }
QLineEdit, QComboBox { background: #10161f; border: 1px solid #354255; border-radius: 6px; padding: 8px; min-height: 20px; selection-background-color: #255c7d; }
QComboBox QAbstractItemView { background: #202b38; color: #e8edf5; selection-background-color: #35485e; }
QPushButton { background: #283444; border: 1px solid #3a4a5e; border-radius: 7px; padding: 9px 14px; font-weight: 600; }
QPushButton:hover { background: #34445a; }
QPushButton:pressed { background: #1b2838; }
QPushButton:disabled { color: #6e7c8f; background: #202832; border-color: #293240; }
QPushButton#primary { background: #68ddb0; color: #10291f; border-color: #68ddb0; }
QPushButton#primary:hover { background: #8aebc5; }
QPushButton#primary:disabled { color: #6e7c8f; background: #283e36; border-color: #304a40; }
QPushButton#quiet { background: transparent; }
QPlainTextEdit { background: #0d1219; border: 1px solid #293240; border-radius: 6px; color: #b9c9da; font-family: Consolas; font-size: 11px; padding: 5px; }
QCheckBox { spacing: 8px; }
QCheckBox::indicator { width: 17px; height: 17px; }
QToolTip { color: #e8edf5; background: #263445; border: 1px solid #44566d; }
"""


class _Signals(QObject):
    done = Signal(object)
    failed = Signal(str)
    progress = Signal(str)


class _Task(QRunnable):
    def __init__(self, action: Callable):
        super().__init__()
        self.action = action
        self.signals = _Signals()

    def run(self):
        try:
            self.signals.done.emit(self.action(self.signals.progress.emit))
        except Exception as exc:
            self.signals.failed.emit(str(exc) or type(exc).__name__)


def _label(text: str, name: str = "", wrap: bool = False) -> QLabel:
    label = QLabel(text)
    label.setObjectName(name)
    label.setWordWrap(wrap)
    label.setTextFormat(Qt.TextFormat.PlainText)
    return label


def launch_game(game: Game) -> None:
    """Do not propagate PyInstaller's private DLL search directory to Steam."""
    if sys.platform != "win32":
        raise PatcherError("Запуск игры доступен только в Windows.")
    ctypes.windll.kernel32.SetDllDirectoryW(None)
    try:
        if game.app_id:
            os.startfile(f"steam://rungameid/{game.app_id}")
        else:
            os.startfile(str(game.exe))
    finally:
        if getattr(sys, "frozen", False):
            ctypes.windll.kernel32.SetDllDirectoryW(str(Path(sys._MEIPASS)))


class MainWindow(QMainWindow):
    def __init__(self, bundle: Bundle, data_dir: Path, *, auto_start: bool = True, auto_updates: bool = True):
        super().__init__()
        self.bundle = bundle
        self.data_dir = data_dir
        self.installer = Installer(data_dir)
        self.game: Game | None = None
        self.result: dict = {}
        self.pool = QThreadPool(self)
        self._task: _Task | None = None
        self._busy = False
        self._gpu: dict = {}
        self.auto_updates = auto_updates
        self.setWindowTitle(f"DLSSG Patcher {__version__}")
        self.resize(1060, 880)
        self.setMinimumSize(900, 790)
        self.setStyleSheet(STYLE)
        root = QWidget()
        self.setCentralWidget(root)
        layout = QVBoxLayout(root)
        layout.setContentsMargins(28, 22, 28, 20)
        layout.setSpacing(13)
        header = QHBoxLayout()
        heading = QVBoxLayout()
        heading.addWidget(_label("DLSSG / SM86", "eyebrow"))
        heading.addWidget(_label("Генерация кадров. Под контролем.", "title"))
        heading.addWidget(_label("Установка, обновления и восстановление — в одном месте", "subtitle"))
        header.addLayout(heading)
        header.addStretch()
        header.addWidget(_label(f"PORTABLE  /  {__version__}", "muted"))
        layout.addLayout(header)

        game_card, game_layout = self._card()
        game_layout.addWidget(_label("01  /  ИГРА", "eyebrow"))
        select_row = QHBoxLayout()
        self.games_combo = QComboBox()
        self.games_combo.setObjectName("games")
        self.games_combo.setMinimumWidth(260)
        self.games_combo.addItem("Выберите игру или укажите путь", None)
        self.games_combo.currentIndexChanged.connect(self._select_game)
        select_row.addWidget(self.games_combo, 1)
        self.folder_button = QPushButton("Выбрать папку")
        self.folder_button.clicked.connect(self._choose_folder)
        self.exe_button = QPushButton("Выбрать EXE")
        self.exe_button.clicked.connect(self._choose_exe)
        select_row.addWidget(self.folder_button)
        select_row.addWidget(self.exe_button)
        game_layout.addLayout(select_row)
        self.path_edit = QLineEdit()
        self.path_edit.setObjectName("gamePath")
        self.path_edit.setPlaceholderText("Путь к папке игры или настоящему игровому EXE")
        self.path_edit.returnPressed.connect(lambda: self.resolve_path(self.path_edit.text()))
        self.path_edit.setToolTip("Вставьте путь и нажмите Enter. Для Unreal Engine нужен EXE в Binaries/Win64.")
        game_layout.addWidget(self.path_edit)
        self.game_note = _label("Сначала выберите игру. Все изменения можно отменить.", "muted", True)
        game_layout.addWidget(self.game_note)
        self.graphics_note = _label("", "warning", True)
        self.graphics_note.hide()
        game_layout.addWidget(self.graphics_note)
        layout.addWidget(game_card)

        info_row = QHBoxLayout()
        gpu_card, gpu_layout = self._card()
        gpu_layout.addWidget(_label("ВИДЕОКАРТА", "eyebrow"))
        self.gpu_label = _label("Определение видеокарты…", "value")
        gpu_layout.addWidget(self.gpu_label)
        self.gpu_detail = _label("Профиль RTX 30: SM86 / PTX / точный режим", "muted", True)
        gpu_layout.addWidget(self.gpu_detail)
        info_row.addWidget(gpu_card, 1)
        bundle_card, bundle_layout = self._card()
        bundle_layout.addWidget(_label("КОМПЛЕКТ ДЛЯ УСТАНОВКИ", "eyebrow"))
        self.bundle_label = _label(bundle.label, "value")
        bundle_layout.addWidget(self.bundle_label)
        self.bundle_detail = _label(f"GitHub · {bundle.revision[:8]} · доступен без интернета", "muted", True)
        bundle_layout.addWidget(self.bundle_detail)
        info_row.addWidget(bundle_card, 1)
        layout.addLayout(info_row)

        status_card, status_layout = self._card()
        status_layout.addWidget(_label("02  /  УСТАНОВКА И ПРОВЕРКА", "eyebrow"))
        self.state_label = _label("Готов к настройке", "state")
        status_layout.addWidget(self.state_label)
        self.state_detail = _label("Установка файлов не означает, что генерация кадров уже работает.", "muted", True)
        status_layout.addWidget(self.state_detail)
        steps_row = QHBoxLayout()
        self.steps = [_label(text, "step") for text in ("1  Файлы установлены", "2  Мод загрузился", "3  Проверено в игре")]
        for step in self.steps:
            steps_row.addWidget(step)
        steps_row.addStretch()
        status_layout.addLayout(steps_row)
        controls = QHBoxLayout()
        controls.addWidget(_label("Загрузчик", "muted"))
        self.proxy_combo = QComboBox()
        self.proxy_combo.setObjectName("proxy")
        self.proxy_combo.addItem("Автоматически", None)
        controls.addWidget(self.proxy_combo)
        controls.addWidget(_label("Предел FG", "muted"))
        self.frames_combo = QComboBox()
        for i in range(1, 4):
            self.frames_combo.addItem(f"До {i + 1}X", i)
        self.frames_combo.setCurrentIndex(2)
        controls.addWidget(self.frames_combo)
        self.approx_checkbox = QCheckBox("Приближённый режим")
        self.approx_checkbox.setToolTip("Может менять изображение. Прирост скорости не гарантирован.")
        controls.addWidget(self.approx_checkbox)
        self.logs_checkbox = QCheckBox("Диагностика")
        self.logs_checkbox.setChecked(True)
        controls.addWidget(self.logs_checkbox)
        controls.addStretch()
        status_layout.addLayout(controls)
        status_layout.addWidget(_label("Множитель выбирается в игре. Для первой проверки Bodycam начните с 2X.", "muted", True))
        actions = QHBoxLayout()
        self.install_button = QPushButton("Установить")
        self.install_button.setObjectName("primary")
        self.install_button.clicked.connect(self._install)
        self.update_button = QPushButton("Обновить")
        self.update_button.clicked.connect(self._install)
        self.check_button = QPushButton("Проверить")
        self.check_button.clicked.connect(self._check)
        self.rollback_button = QPushButton("Откатить")
        self.rollback_button.clicked.connect(lambda: self._operation("Восстановление…", "rollback"))
        self.uninstall_button = QPushButton("Удалить")
        self.uninstall_button.clicked.connect(lambda: self._operation("Удаление мода…", "uninstall"))
        self.settings_button = QPushButton("Сохранить настройки")
        self.settings_button.clicked.connect(self._save_settings)
        for button in (self.install_button, self.update_button, self.check_button, self.rollback_button, self.uninstall_button, self.settings_button):
            actions.addWidget(button)
        status_layout.addLayout(actions)
        layout.addWidget(status_card)

        bottom = QHBoxLayout()
        self.launch_button = QPushButton("Запустить игру")
        self.launch_button.clicked.connect(self._launch)
        self.confirm_button = QPushButton("Изображение проверено")
        self.confirm_button.clicked.connect(self._confirm_visual)
        self.logs_button = QPushButton("Открыть журнал")
        self.logs_button.clicked.connect(self._open_logs)
        self.fetch_button = QPushButton("Проверить GitHub")
        self.fetch_button.clicked.connect(self.fetch_updates)
        for button in (self.launch_button, self.confirm_button, self.logs_button):
            bottom.addWidget(button)
        bottom.addStretch()
        bottom.addWidget(self.fetch_button)
        layout.addLayout(bottom)
        self.activity = QPlainTextEdit()
        self.activity.setObjectName("activity")
        self.activity.setReadOnly(True)
        self.activity.setMaximumBlockCount(300)
        self.activity.setMaximumHeight(104)
        layout.addWidget(self.activity)
        self.footer = _label("Обновления скачиваются в кэш. Игра меняется только по выбранному действию.", "muted", True)
        layout.addWidget(self.footer)
        self._update_enabled()
        if auto_start:
            QTimer.singleShot(50, self.initialize)

    @staticmethod
    def _card():
        frame = QFrame()
        frame.setObjectName("card")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(17, 13, 17, 13)
        layout.setSpacing(10)
        return frame, layout

    def log(self, message: str):
        self.activity.appendPlainText(str(message))

    def _run(self, title: str, action: Callable, callback: Callable):
        if self._busy:
            return
        self._busy = True
        self.footer.setText(title)
        self._update_enabled()
        task = _Task(action)
        self._task = task
        task.signals.progress.connect(self.log)

        def done(result):
            self._busy = False
            self._task = None
            self.footer.setText("Готово. Изменения игры выполняются только по выбранному действию.")
            try:
                callback(result)
            except Exception as exc:
                self._error(str(exc))
            self._update_enabled()

        def failed(message):
            self._busy = False
            self._task = None
            self._error(message)
            self._update_enabled()

        task.signals.done.connect(done)
        task.signals.failed.connect(failed)
        self.pool.start(task)

    def _error(self, message: str):
        self.log(f"Ошибка: {message}")
        self.footer.setText(message)

    def initialize(self):
        def finished(result):
            games, gpu = result
            self._gpu = gpu
            self.gpu_label.setText(gpu.get("name") or "Видеокарта не определена")
            memory = gpu.get("memory_mib")
            self.gpu_detail.setText(f"{memory or '?'} МиБ VRAM · драйвер {gpu.get('driver', '?')} · SM {gpu.get('compute_cap', '?')}")
            self.games_combo.blockSignals(True)
            for game in games:
                self.games_combo.addItem(game.name, game)
            index = next((i for i in range(1, self.games_combo.count()) if self.games_combo.itemData(i).app_id == "2406770"), 0)
            self.games_combo.setCurrentIndex(index)
            self.games_combo.blockSignals(False)
            if index:
                self._set_game(self.games_combo.itemData(index))
            self.log("Встроенный комплект готов. Резервные копии: " + str(self.data_dir))
            if self.auto_updates:
                QTimer.singleShot(150, self.fetch_updates)
        self._run("Поиск Steam-библиотек и видеокарты…", lambda _: (environment.discover_steam_games(), environment.gpu_info()), finished)

    def _select_game(self, index):
        game = self.games_combo.itemData(index)
        if game:
            try:
                self._set_game(game)
            except Exception as exc:
                self._error(str(exc))

    def _set_game(self, game: Game):
        self.game = environment.game_for_exe(game.exe)
        self.path_edit.setText(str(self.game.exe))
        if self.game.app_id == "2406770":
            self.game_note.setObjectName("warning")
            self.game_note.setText(f"Bodycam · сборка {self.game.build_id or '?'} · экспериментальный профиль. Проверяйте артефакты и стабильность; совместимость не гарантирована.")
        else:
            self.game_note.setObjectName("muted")
            self.game_note.setText("Нужна игра Windows x64 / DirectX 12 с интеграцией DLSS Frame Generation.")
        self.game_note.style().unpolish(self.game_note)
        self.game_note.style().polish(self.game_note)
        self.refresh()

    def resolve_path(self, text: str):
        try:
            path = Path(text.strip().strip('"')).expanduser()
            if path.is_dir():
                candidates = environment.find_game_exes(path)
                if not candidates:
                    raise PatcherError("В этой папке не найден игровой EXE.")
                if len(candidates) > 1:
                    from PySide6.QtWidgets import QInputDialog
                    choice, accepted = QInputDialog.getItem(self, "Игровой EXE", "Выберите EXE, который выполняет рендеринг:", [str(p) for p in candidates], 0, False)
                    if not accepted:
                        return
                    path = Path(choice)
                else:
                    path = candidates[0]
            self._set_game(environment.game_for_exe(path))
        except Exception as exc:
            self._error(str(exc))

    def _choose_folder(self):
        path = QFileDialog.getExistingDirectory(self, "Папка игры", str(self.game.install_root or self.game.directory) if self.game else "")
        if path:
            self.resolve_path(path)

    def _choose_exe(self):
        path, _ = QFileDialog.getOpenFileName(self, "Игровой EXE", str(self.game.directory) if self.game else "", "Приложения Windows (*.exe)")
        if path:
            self.resolve_path(path)

    def refresh(self):
        if not self.game:
            return
        self.game = environment.game_for_exe(self.game.exe)
        graphics = environment.bodycam_graphics_settings() if self.game.app_id == "2406770" else {}
        fg_method = graphics.get("fg_method")
        if fg_method:
            detail = f"В игре сохранено: генерация — {fg_method}; масштабирование — {graphics.get('upscaling_method', '?')}."
            if "dlss" not in str(fg_method).casefold():
                detail += " Для проверки мода выберите DLSS Frame Generation в настройках игры."
            self.graphics_note.setText(detail)
            self.graphics_note.show()
        else:
            self.graphics_note.hide()
        result = self.installer.inspect(self.game, self.bundle)
        self._display_result(result)

    def _display_result(self, result: dict):
        self.result = result
        state = result.get("state", "absent")
        titles = {"absent": "Мод ещё не установлен", "installed": "Файлы установлены", "loaded": "Мод загрузился", "verified": "Проверено вами в игре", "failed": "Проверка выявила проблему", "stale": "Нужна повторная проверка", "modified": "Файлы изменены вне патчера"}
        self.state_label.setText(titles.get(state, state))
        self.state_detail.setText(str(result.get("message", "")))
        if result.get("revision"):
            self.log(f"Установлено: {result.get('proxy')} · {str(result['revision'])[:8]}")
        installed = bool(result.get("installed"))
        for index, step in enumerate(self.steps):
            active = (installed and index == 0) or (state in {"loaded", "verified"} and index == 1) or (state == "verified" and index == 2)
            step.setStyleSheet("color: #83edbf; background: #203c33; padding: 7px 10px; border-radius: 6px;" if active else "color: #a9b7c9; background: #252e3b; padding: 7px 10px; border-radius: 6px;")
        self.proxy_combo.clear()
        self.proxy_combo.addItem("Автоматически", None)
        for proxy in result.get("available_proxies", []):
            self.proxy_combo.addItem(proxy, proxy)
        current = result.get("proxy")
        if current and self.proxy_combo.findData(current) < 0:
            self.proxy_combo.addItem(current, current)
        if current:
            self.proxy_combo.setCurrentIndex(self.proxy_combo.findData(current))
        settings = result.get("settings", {})
        if settings and installed:
            self.approx_checkbox.setChecked(bool(settings.get("hardware_bilinear", 0)))
            self.logs_checkbox.setChecked(bool(settings.get("diagnostics", True)))
            index = self.frames_combo.findData(int(settings.get("max_generated_frames", 3)))
            self.frames_combo.setCurrentIndex(max(0, index))
        elif not installed:
            self.logs_checkbox.setChecked(True)
            self.frames_combo.setCurrentIndex(2)
            self.approx_checkbox.setChecked(False)
        self._update_enabled()

    def _update_enabled(self):
        ready = bool(self.game) and not self._busy
        installed = bool(self.result.get("installed"))
        for control in (self.games_combo, self.folder_button, self.exe_button, self.path_edit, self.fetch_button):
            control.setEnabled(not self._busy)
        self.install_button.setEnabled(ready and not installed and self.result.get("can_install", True))
        self.update_button.setEnabled(ready and installed and self.result.get("revision") != self.bundle.revision)
        for control in (self.check_button, self.launch_button):
            control.setEnabled(ready)
        for control in (self.rollback_button, self.uninstall_button, self.settings_button, self.logs_button):
            control.setEnabled(ready and installed)
        self.confirm_button.setEnabled(ready and self.result.get("state") in {"loaded", "verified"})
        self.proxy_combo.setEnabled(ready and not installed)
        for control in (self.frames_combo, self.approx_checkbox):
            control.setEnabled(ready and installed)
        self.logs_checkbox.setEnabled(ready)

    def _operation(self, title, method, **kwargs):
        if not self.game:
            return
        game = environment.game_for_exe(self.game.exe)
        self.game = game
        def finished(result):
            self.refresh()
            if result.get("state") == "failed":
                self._error(str(result.get("message", "Операция не выполнена")))
                self.state_detail.setText(str(result.get("message", "Операция не выполнена")))
            else:
                self.log(str(result.get("message", "Готово")))
        self._run(title, lambda _: getattr(self.installer, method)(game, **kwargs), finished)

    def _install(self):
        self._operation("Установка комплекта и создание резервной копии…", "install", bundle=self.bundle, proxy=self.proxy_combo.currentData(), diagnostics=self.logs_checkbox.isChecked())

    def _save_settings(self):
        self._operation("Сохранение настроек…", "configure", diagnostics=self.logs_checkbox.isChecked(), hardware_bilinear=int(self.approx_checkbox.isChecked()), max_generated_frames=self.frames_combo.currentData())

    def _check(self):
        self._operation("Проверка файлов и свежих журналов…", "check")

    def fetch_updates(self):
        current = self.bundle
        def finished(bundle):
            self.bundle = bundle
            self.bundle_label.setText(bundle.label)
            self.bundle_detail.setText(f"GitHub · {bundle.revision[:8]} · доступен без интернета")
            self.log("Новая версия скачана. Нажмите «Обновить» для выбранной игры." if bundle.revision != current.revision else "GitHub проверен: комплект актуален.")
            self.refresh()
        self._run("Проверка GitHub. Установленная игра не изменяется…", lambda progress: packages.check_for_update(self.data_dir, current, progress=progress), finished)

    def _launch(self):
        if self.game:
            try:
                launch_game(self.game)
                self.log("Игра запущена. Выберите DLSS Frame Generation 2X, затем нажмите «Проверить» в патчере.")
            except Exception as exc:
                self._error(str(exc))

    def _confirm_visual(self):
        box = QMessageBox(self)
        box.setWindowTitle("Результат проверки в игре")
        box.setText("Вы включили DLSS Frame Generation в игре и проверили изображение?")
        box.setInformativeText("Отмечайте успешную проверку только после игрового эпизода без артефактов и сбоев. Наличие журнала этого не подтверждает.")
        good = box.addButton("Да, всё работает", QMessageBox.ButtonRole.AcceptRole)
        bad = box.addButton("Есть артефакты или сбои", QMessageBox.ButtonRole.DestructiveRole)
        box.addButton("Отмена", QMessageBox.ButtonRole.RejectRole)
        box.exec()
        if box.clickedButton() in (good, bad):
            self._operation("Сохранение результата проверки…", "record_visual_confirmation", ok=box.clickedButton() == good)

    def _open_logs(self):
        if self.game:
            directory = self.game.directory / "dlssg_sm86" / "logs"
            if directory.is_dir():
                QDesktopServices.openUrl(QUrl.fromLocalFile(str(directory)))
            else:
                self.log("Журнал ещё не создан. Включите диагностику, сохраните настройки и перезапустите игру.")

    def closeEvent(self, event: QCloseEvent):
        if self._busy:
            self.footer.setText("Дождитесь завершения операции перед закрытием окна.")
            event.ignore()
        else:
            event.accept()
