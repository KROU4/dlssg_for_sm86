import hashlib
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from patcher_app.installer import Installer
from patcher_app.models import Bundle, Game, INI_NAME, PROXY_NAMES


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.game_dir = root / "Игра с пробелами"
        self.game_dir.mkdir()
        self.exe = self.game_dir / "Bodycam-Win64-Shipping.exe"
        self.exe.write_bytes(b"fake-pe")
        self.game = Game(self.exe, "Bodycam", "2406770", "25228199")
        self.bundle_dir = root / "bundle"
        self.bundle_dir.mkdir()
        for name in PROXY_NAMES:
            (self.bundle_dir / name).write_bytes(("new-" + name).encode())
        (self.bundle_dir / INI_NAME).write_text(
            "[Compatibility]\nRouter=SM86\nKernelImage=PTX\nHardwareBilinear=0\n"
            "[FrameGeneration]\nMaxGeneratedFrames=3\n[Logging]\nLevel=1\n", encoding="utf-8")
        files = {name: digest(self.bundle_dir / name) for name in (*PROXY_NAMES, INI_NAME)}
        self.bundle = Bundle(self.bundle_dir, "rev1", "Native test", files)
        self.installer = Installer(root / "patcher-data", process_checker=lambda game: True)
        self.env = patch("patcher_app.environment.inspect_exe", return_value={"machine": 0x8664, "imports": ["version.dll", "winmm.dll"]})
        self.anti = patch("patcher_app.environment.detect_anticheat", return_value=[])
        self.valid = patch("patcher_app.packages.validate_bundle", return_value=True)
        self.env.start(); self.anti.start(); self.valid.start()

    def tearDown(self):
        self.env.stop(); self.anti.stop(); self.valid.stop()
        self.temp.cleanup()

    def test_install_repeat_update_rollback_and_uninstall(self):
        original_ini = "[Custom]\nKeepMe=yes\n[Logging]\nLevel=0\n"
        (self.game_dir / INI_NAME).write_text(original_ini, encoding="utf-8")
        installed = self.installer.install(self.game, self.bundle)
        self.assertEqual("installed", installed["state"])
        self.assertEqual("version.dll", installed["proxy"])
        config = (self.game_dir / INI_NAME).read_text(encoding="utf-8")
        self.assertIn("KeepMe=yes", config)
        self.assertIn("Level=2", config)
        self.assertEqual(1, config.count("[Compatibility]"))
        self.assertFalse((self.game_dir / "winmm.dll").exists())
        history_count = len(self.installer._load_record(self.game)["history"])
        self.assertEqual("installed", self.installer.install(self.game, self.bundle)["state"])
        self.assertEqual(history_count, len(self.installer._load_record(self.game)["history"]))

        second_dir = self.bundle_dir.parent / "bundle2"
        second_dir.mkdir()
        for name in PROXY_NAMES:
            (second_dir / name).write_bytes(("v2-" + name).encode())
        (second_dir / INI_NAME).write_text((self.bundle_dir / INI_NAME).read_text(), encoding="utf-8")
        bundle2 = Bundle(second_dir, "rev2", "two", {})
        self.assertEqual("installed", self.installer.install(self.game, bundle2)["state"])
        self.assertEqual(b"v2-version.dll", (self.game_dir / "version.dll").read_bytes())
        self.assertEqual("installed", self.installer.rollback(self.game)["state"])
        self.assertEqual(b"new-version.dll", (self.game_dir / "version.dll").read_bytes())
        self.assertEqual("absent", self.installer.uninstall(self.game)["state"])
        self.assertFalse((self.game_dir / "version.dll").exists())
        self.assertEqual(original_ini, (self.game_dir / INI_NAME).read_text(encoding="utf-8"))

    def test_foreign_proxy_is_preserved_and_next_import_used(self):
        foreign = self.game_dir / "version.dll"
        foreign.write_bytes(b"foreign")
        result = self.installer.install(self.game, self.bundle)
        self.assertEqual("winmm.dll", result["proxy"])
        self.assertEqual(b"foreign", foreign.read_bytes())
        self.installer.uninstall(self.game)
        self.assertEqual(b"foreign", foreign.read_bytes())

    def test_modified_owned_file_refuses_update_uninstall_and_rollback(self):
        self.installer.install(self.game, self.bundle)
        (self.game_dir / "version.dll").write_bytes(b"user change")
        self.assertEqual("modified", self.installer.inspect(self.game)["state"])
        self.assertEqual("failed", self.installer.uninstall(self.game)["state"])
        self.assertEqual(b"user change", (self.game_dir / "version.dll").read_bytes())
        self.assertEqual("failed", self.installer.rollback(self.game)["state"])

    def test_configure_preserves_unknown_keys_and_rolls_back(self):
        self.installer.install(self.game, self.bundle)
        ini = self.game_dir / INI_NAME
        ini.write_text(ini.read_text() + "[User]\nUnknown=42\n", encoding="utf-8")
        record = self.installer._load_record(self.game)
        record["files"][INI_NAME] = digest(ini)
        self.installer._save_record(self.game, record)
        result = self.installer.configure(self.game, diagnostics=False, hardware_bilinear=True, max_generated_frames=1)
        self.assertEqual("installed", result["state"])
        text = ini.read_text(encoding="utf-8")
        self.assertIn("Unknown=42", text)
        self.assertIn("HardwareBilinear=1", text)
        self.assertIn("MaxGeneratedFrames=1", text)
        self.assertIn("Level=1", text)
        self.installer.rollback(self.game)
        self.assertIn("Unknown=42", ini.read_text(encoding="utf-8"))

    def test_stale_build_and_explicit_visual_verification(self):
        self.installer.install(self.game, self.bundle)
        newer = Game(self.exe, "Bodycam", "2406770", "new-build")
        self.assertEqual("stale", self.installer.inspect(newer)["state"])
        self.assertEqual("failed", self.installer.record_visual_confirmation(self.game, True)["state"])
        log_dir = self.game_dir / "dlssg_sm86" / "logs"
        log_dir.mkdir(parents=True)
        log = log_dir / "native_1.jsonl"
        time.sleep(0.01)
        log.write_text(json.dumps({"event": "configuration", "runtime": "native_pipeline",
                                   "router": 86, "pid": 24008}) + "\n" +
                       json.dumps({"event": "ngx_driver_connected", "feature_id": 11,
                                   "pid": 24008}) + "\n", encoding="utf-8")
        self.assertEqual("loaded", self.installer.check(self.game)["state"])
        self.assertEqual("verified", self.installer.record_visual_confirmation(self.game, True, "2X clean")["state"])
        self.assertEqual("verified", self.installer.check(self.game)["state"])

    def test_check_rebaselines_new_build_without_reinstall(self):
        self.installer.install(self.game, self.bundle)
        newer = Game(self.exe, "Bodycam", "2406770", "next-build")
        result = self.installer.check(newer)
        self.assertEqual("installed", result["state"])
        self.assertEqual("next-build", self.installer._load_record(newer)["game"]["build_id"])

    def test_runtime_failure_is_persisted(self):
        self.installer.install(self.game, self.bundle)
        log_dir = self.game_dir / "dlssg_sm86" / "logs"
        log_dir.mkdir(parents=True)
        (log_dir / "native_2.jsonl").write_text(
            json.dumps({"event": "install_failed"}) + "\n", encoding="utf-8")
        self.assertEqual("failed", self.installer.check(self.game)["state"])
        self.assertEqual("failed", self.installer.inspect(self.game)["state"])

    def test_plain_text_log_never_claims_loaded(self):
        self.installer.install(self.game, self.bundle)
        log_dir = self.game_dir / "dlssg_sm86" / "logs"
        log_dir.mkdir(parents=True)
        log = log_dir / "native_1.jsonl"
        log.write_text("loaded successfully\n" + json.dumps({"event": "ngx_driver_connected",
                                                               "pid": 1}), encoding="utf-8")
        self.assertEqual("installed", self.installer.check(self.game)["state"])

    def test_exact_native_log_fixture_proves_loaded_only_for_same_pid_and_file(self):
        self.installer.install(self.game, self.bundle)
        log_dir = self.game_dir / "dlssg_sm86" / "logs"
        log_dir.mkdir(parents=True)
        fixture = (
            '{"cuda_buffer_clear":true,"disabled_fusions":0,"event":"configuration",'
            '"hardware_bilinear":false,"image_patches":true,"kernel_image":"ptx",'
            '"max_generated":3,"optimized":true,"pid":24008,"router":86,'
            '"runtime":"native_pipeline","self_contained":true}\n'
            '{"event":"ngx_driver_connected","feature_file_discovery_required":false,'
            '"feature_id":11,"pid":24008}\n'
        )
        (log_dir / "native_24008.jsonl").write_text(fixture, encoding="utf-8")
        self.assertEqual("loaded", self.installer.check(self.game)["state"])

    def test_old_touched_log_and_split_markers_do_not_prove_loaded(self):
        log_dir = self.game_dir / "dlssg_sm86" / "logs"
        log_dir.mkdir(parents=True)
        old = log_dir / "native_old.jsonl"
        old.write_text(
            json.dumps({"event": "configuration", "runtime": "native_pipeline", "router": 86, "pid": 7}) + "\n" +
            json.dumps({"event": "ngx_driver_connected", "pid": 7}) + "\n", encoding="utf-8")
        self.installer.install(self.game, self.bundle)
        old.touch()
        self.assertEqual("installed", self.installer.check(self.game)["state"])
        (log_dir / "one.jsonl").write_text(
            json.dumps({"event": "configuration", "runtime": "native_pipeline", "router": 86, "pid": 9}),
            encoding="utf-8")
        (log_dir / "two.jsonl").write_text(
            json.dumps({"event": "ngx_driver_connected", "pid": 9}), encoding="utf-8")
        self.assertEqual("installed", self.installer.check(self.game)["state"])

    def test_update_with_proxy_change_uninstall_removes_latest_proxy(self):
        self.installer.install(self.game, self.bundle)
        result = self.installer.install(self.game, self.bundle, proxy="winmm.dll")
        self.assertEqual("winmm.dll", result["proxy"])
        self.assertEqual("absent", self.installer.uninstall(self.game)["state"])
        self.assertFalse((self.game_dir / "winmm.dll").exists())
        self.assertFalse((self.game_dir / "version.dll").exists())

    def test_next_mutation_recovers_prepared_crash_journal(self):
        target = self.game_dir / "winmm.dll"
        target.write_bytes(b"before")
        backup = self.installer.data_dir / "backups" / self.installer._game_id(self.game) / "crash"
        backup.mkdir(parents=True)
        (backup / "winmm.dll").write_bytes(b"before")
        operation = {"backup": str(backup), "names": ["winmm.dll"], "existing": ["winmm.dll"],
                     "backup_hashes": {"winmm.dll": digest(backup / "winmm.dll")}, "record_before": None}
        self.installer._journal_path(self.game).write_text(
            json.dumps({"operation": operation, "previous_record": None}), encoding="utf-8")
        target.write_bytes(b"partial")
        result = self.installer.install(self.game, self.bundle)
        self.assertEqual("installed", result["state"])
        self.assertFalse(self.installer._journal_path(self.game).exists())

    def test_crash_recovery_waits_until_game_is_closed(self):
        target = self.game_dir / "winmm.dll"
        target.write_bytes(b"partial")
        backup = self.installer.data_dir / "backups" / self.installer._game_id(self.game) / "closed"
        backup.mkdir(parents=True)
        (backup / "winmm.dll").write_bytes(b"before")
        operation = {"backup": str(backup), "names": ["winmm.dll"], "existing": ["winmm.dll"],
                     "backup_hashes": {"winmm.dll": digest(backup / "winmm.dll")}, "record_before": None}
        self.installer._journal_path(self.game).write_text(
            json.dumps({"operation": operation, "previous_record": None}), encoding="utf-8")
        running = Installer(self.installer.data_dir, process_checker=lambda game: False)
        self.assertEqual("failed", running.install(self.game, self.bundle)["state"])
        self.assertEqual(b"partial", target.read_bytes())
        self.assertTrue(self.installer._journal_path(self.game).exists())

    def test_record_write_failure_restores_initial_files_immediately(self):
        real = self.installer._write_json_atomic
        failed = False

        def fail_record(path, value):
            nonlocal failed
            if path == self.installer._record_path(self.game) and not failed:
                failed = True
                raise PermissionError("record locked")
            return real(path, value)

        with patch.object(self.installer, "_write_json_atomic", side_effect=fail_record):
            result = self.installer.install(self.game, self.bundle)
        self.assertEqual("failed", result["state"])
        self.assertFalse((self.game_dir / "version.dll").exists())
        self.assertFalse((self.game_dir / INI_NAME).exists())
        self.assertFalse(self.installer._journal_path(self.game).exists())

    def test_rollback_write_failure_keeps_current_version_and_record(self):
        self.installer.install(self.game, self.bundle)
        second = self.bundle_dir.parent / "second"
        second.mkdir()
        for name in PROXY_NAMES:
            (second / name).write_bytes(("second-" + name).encode())
        (second / INI_NAME).write_bytes((self.bundle_dir / INI_NAME).read_bytes())
        self.installer.install(self.game, Bundle(second, "rev2", "two", {}))
        real = self.installer._write_bytes_atomic
        failed = False

        def fail_old_proxy(path, content):
            nonlocal failed
            if path.name == "version.dll" and content == b"new-version.dll" and not failed:
                failed = True
                raise PermissionError("locked")
            return real(path, content)

        with patch.object(self.installer, "_write_bytes_atomic", side_effect=fail_old_proxy):
            result = self.installer.rollback(self.game)
        self.assertEqual("failed", result["state"])
        self.assertEqual(b"second-version.dll", (self.game_dir / "version.dll").read_bytes())
        self.assertEqual("rev2", self.installer._load_record(self.game)["revision"])

    def test_corrupt_journal_cannot_escape_backup_directory(self):
        outside = self.game_dir / "outside.txt"
        outside.write_text("keep", encoding="utf-8")
        operation = {"backup": str(self.game_dir), "names": ["outside.txt"],
                     "existing": ["outside.txt"], "backup_hashes": {"outside.txt": digest(outside)}}
        self.installer._journal_path(self.game).write_text(
            json.dumps({"operation": operation, "previous_record": None}), encoding="utf-8")
        result = self.installer.install(self.game, self.bundle)
        self.assertEqual("failed", result["state"])
        self.assertEqual("keep", outside.read_text(encoding="utf-8"))

    def test_malformed_record_cannot_delete_parent_relative_victim(self):
        victim = self.game_dir.parent / "victim.txt"
        victim.write_text("keep", encoding="utf-8")
        record_path = self.installer._record_path(self.game)
        record_path.write_text(json.dumps({"proxy": "../victim.txt", "files": {},
                                           "revision": "old"}), encoding="utf-8")
        result = self.installer.install(self.game, self.bundle)
        self.assertEqual("failed", result["state"])
        self.assertEqual("keep", victim.read_text(encoding="utf-8"))

    def test_second_portable_copy_refuses_to_adopt_existing_project_dll(self):
        self.assertEqual("installed", self.installer.install(self.game, self.bundle)["state"])
        other = Installer(Path(self.temp.name) / "other-data", process_checker=lambda game: True)
        result = other.install(self.game, self.bundle)
        self.assertEqual("failed", result["state"])
        self.assertIn("другой копией", result["message"])
        self.assertTrue((self.game_dir / "version.dll").exists())
        self.assertFalse((self.game_dir / "winmm.dll").exists())

    def test_second_copy_rejects_older_dlssg_proxy_with_unknown_hash(self):
        self.assertEqual("installed", self.installer.install(self.game, self.bundle)["state"])
        newer_dir = self.bundle_dir.parent / "newer-bundle"
        newer_dir.mkdir()
        for name in PROXY_NAMES:
            (newer_dir / name).write_bytes(("new-revision-" + name).encode())
        (newer_dir / INI_NAME).write_bytes((self.bundle_dir / INI_NAME).read_bytes())
        newer_files = {name: digest(newer_dir / name) for name in (*PROXY_NAMES, INI_NAME)}
        newer = Bundle(newer_dir, "different-revision", "new", newer_files)
        other = Installer(Path(self.temp.name) / "new-data", process_checker=lambda game: True)
        with patch.object(other, "_looks_like_dlssg_proxy",
                          side_effect=lambda path: path.name == "version.dll"):
            result = other.install(self.game, newer)
        self.assertEqual("failed", result["state"])
        self.assertIn("другой копией", result["message"])
        self.assertTrue((self.game_dir / "version.dll").exists())
        self.assertFalse((self.game_dir / "winmm.dll").exists())

    def test_bundled_native_dll_has_revision_independent_ngx_signature(self):
        project_dll = Path(__file__).resolve().parents[1] / "version.dll"
        self.assertTrue(self.installer._looks_like_dlssg_proxy(project_dll))

    def test_cp1251_ini_is_rejected_without_modification(self):
        ini = self.game_dir / INI_NAME
        original = "; настройка\n[Logging]\nLevel=1\n".encode("cp1251")
        ini.write_bytes(original)
        result = self.installer.install(self.game, self.bundle)
        self.assertEqual("failed", result["state"])
        self.assertIn("UTF-8", result["message"])
        self.assertEqual(original, ini.read_bytes())
        self.assertFalse((self.game_dir / "version.dll").exists())

    def test_nonsteam_exe_identity_change_invalidates_verification(self):
        game = Game(self.exe, "Manual game")
        self.installer.install(game, self.bundle)
        self.exe.write_bytes(b"changed fake pe")
        self.assertEqual("stale", self.installer.inspect(game)["state"])

    def test_missing_ini_key_uses_explicit_setting_and_history_is_linear(self):
        current = self.game_dir / "custom.ini"
        current.write_text("[Custom]\nX=1\n", encoding="utf-8")
        merged = self.installer._merge_ini(
            current, current, {("Logging", "Level"): "1"})
        self.assertIn("Level=1", merged)
        self.installer.install(self.game, self.bundle)
        for value in (1, 2, 3, 1):
            self.installer.configure(self.game, max_generated_frames=value)
        record = self.installer._load_record(self.game)
        self.assertEqual(5, len(record["history"]))
        self.assertTrue(all("history" not in (item.get("record_before") or {}) for item in record["history"]))

    def test_partial_write_is_restored_and_journal_removed(self):
        original = b"original"
        target = self.game_dir / "version.dll"
        target.write_bytes(original)
        calls = 0
        real = self.installer._write_bytes_atomic

        def fail_second(path, content):
            nonlocal calls
            calls += 1
            if calls == 3:  # journal, proxy, then INI
                raise PermissionError("locked")
            return real(path, content)

        with patch.object(self.installer, "_write_bytes_atomic", side_effect=fail_second):
            # Existing version.dll is foreign, so winmm is chosen; its initial state is absent.
            result = self.installer.install(self.game, self.bundle)
        self.assertEqual("failed", result["state"])
        self.assertEqual(original, target.read_bytes())
        self.assertFalse((self.game_dir / "winmm.dll").exists())
        self.assertFalse(self.installer._journal_path(self.game).exists())

    def test_lock_and_closed_game_fail_gracefully(self):
        locked = Installer(self.installer.data_dir, process_checker=lambda game: False)
        self.assertEqual("failed", locked.install(self.game, self.bundle)["state"])
        lock_path = self.installer.data_dir / "locks" / f"{self.installer._game_id(self.game)}.lock"
        lock_path.write_text("other", encoding="ascii")
        self.assertEqual("failed", self.installer.install(self.game, self.bundle)["state"])

    def test_stale_process_lock_is_recovered(self):
        lock_path = self.installer.data_dir / "locks" / f"{self.installer._game_id(self.game)}.lock"
        lock_path.write_text("999999999", encoding="ascii")
        result = self.installer.install(self.game, self.bundle)
        self.assertEqual("installed", result["state"])
        self.assertFalse(lock_path.exists())


if __name__ == "__main__":
    unittest.main()
