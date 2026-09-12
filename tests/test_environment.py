from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from patcher_app import environment
from patcher_app.models import Game, PatcherError


class VdfAndSteamTests(unittest.TestCase):
    def test_vdf_parser_handles_escaped_paths_and_comments(self) -> None:
        parsed = environment._parse_vdf(
            '"libraryfolders" { // comment\n "0" { "path" "G:\\\\Steam \\\"Games\\\"" } }'
        )
        self.assertEqual(parsed["libraryfolders"]["0"]["path"], 'G:\\Steam "Games"')

    def test_vdf_parser_preserves_unknown_backslash_escape(self) -> None:
        parsed = environment._parse_vdf('"path" "G:\\SteamLibrary"')
        self.assertEqual(parsed["path"], "G:\\SteamLibrary")

    def test_discovery_prioritizes_bodycam_shipping_exe_and_reads_build(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            library = Path(temp)
            steamapps = library / "steamapps"
            bodycam = steamapps / "common" / "Bodycam"
            shipping = bodycam / "Bodycam" / "Binaries" / "Win64" / "Bodycam-Win64-Shipping.exe"
            other = steamapps / "common" / "Other" / "Other.exe"
            shipping.parent.mkdir(parents=True)
            other.parent.mkdir(parents=True)
            shipping.write_bytes(b"MZ")
            (bodycam / "Bodycam.exe").write_bytes(b"MZ")
            other.write_bytes(b"MZ")
            (steamapps / "appmanifest_2406770.acf").write_text(
                '"AppState" { "appid" "2406770" "name" "Bodycam" "installdir" "Bodycam" "buildid" "25228199" }',
                encoding="utf-8",
            )
            (steamapps / "appmanifest_1.acf").write_text(
                '"AppState" { "appid" "1" "name" "Other" "installdir" "Other" "buildid" "2" }',
                encoding="utf-8",
            )
            with mock.patch.object(environment, "_steam_libraries", return_value=[library]):
                games = environment.discover_steam_games()
            self.assertEqual(games[0].app_id, "2406770")
            self.assertEqual(games[0].build_id, "25228199")
            self.assertEqual(games[0].exe, shipping.resolve())

    def test_game_for_exe_refreshes_manifest_build(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            steamapps = Path(temp) / "steamapps"
            exe = steamapps / "common" / "Bodycam" / environment.BODYCAM_EXE
            exe.parent.mkdir(parents=True)
            exe.write_bytes(b"MZ")
            manifest = steamapps / "appmanifest_2406770.acf"
            manifest.write_text(
                '"AppState" { "appid" "2406770" "name" "Bodycam" "installdir" "Bodycam" "buildid" "999" }',
                encoding="utf-8",
            )
            game = environment.game_for_exe(exe)
            self.assertEqual(game.build_id, "999")
            self.assertEqual(game.exe, exe.resolve())

    def test_game_for_exe_replaces_bodycam_root_launcher_only(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            steamapps = Path(temp) / "steamapps"
            root = steamapps / "common" / "Bodycam"
            launcher = root / "Bodycam.exe"
            shipping = root / environment.BODYCAM_EXE
            alternate = root / "Tools" / "BodycamBenchmark.exe"
            for path in (launcher, shipping, alternate):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"MZ")
            (steamapps / "appmanifest_2406770.acf").write_text(
                '"AppState" { "appid" "2406770" "name" "Bodycam" "installdir" "Bodycam" "buildid" "999" }',
                encoding="utf-8",
            )
            self.assertEqual(environment.game_for_exe(launcher).exe, shipping.resolve())
            self.assertEqual(environment.game_for_exe(alternate).exe, alternate.resolve())


class ExecutableTests(unittest.TestCase):
    def test_find_game_exes_filters_helpers_and_prefers_shipping(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            shipping = root / environment.BODYCAM_EXE
            shipping.parent.mkdir(parents=True)
            shipping.write_bytes(b"")
            (root / "Bodycam.exe").write_bytes(b"")
            helper = root / "Engine" / "Binaries" / "Win64" / "CrashReportClient.exe"
            helper.parent.mkdir(parents=True)
            helper.write_bytes(b"")
            results = environment.find_game_exes(root)
            self.assertEqual(results[0], shipping.resolve())
            self.assertNotIn(helper.resolve(), results)

    def test_inspect_exe_returns_lowercase_imports(self) -> None:
        fake_pe = mock.Mock()
        fake_pe.FILE_HEADER.Machine = 0x8664
        fake_pe.DIRECTORY_ENTRY_IMPORT = [mock.Mock(dll=b"VERSION.DLL"), mock.Mock(dll=b"KERNEL32.dll")]
        fake_pe.DIRECTORY_ENTRY_DELAY_IMPORT = [mock.Mock(dll=b"WINHTTP.DLL")]
        with tempfile.TemporaryDirectory() as temp:
            exe = Path(temp) / "game.exe"
            exe.write_bytes(b"MZstub")
            with mock.patch.object(environment.pefile, "PE", return_value=fake_pe):
                result = environment.inspect_exe(exe)
        self.assertEqual(result["machine"], 0x8664)
        self.assertEqual(result["imports"], ["version.dll", "kernel32.dll"])
        self.assertEqual(result["delay_imports"], ["winhttp.dll"])
        fake_pe.close.assert_called_once()

    def test_inspect_exe_rejects_32_bit(self) -> None:
        fake_pe = mock.Mock()
        fake_pe.FILE_HEADER.Machine = 0x14C
        with tempfile.TemporaryDirectory() as temp:
            exe = Path(temp) / "game.exe"
            exe.write_bytes(b"MZstub")
            with mock.patch.object(environment.pefile, "PE", return_value=fake_pe):
                with self.assertRaisesRegex(PatcherError, "64-битные"):
                    environment.inspect_exe(exe)


class RuntimeTests(unittest.TestCase):
    def test_bodycam_graphics_settings_returns_reads_only_allowlisted_values(self) -> None:
        settings = {
            "FG Method": {"newValue": 1, "incrementedValue": 1, "valueName": "AMD FSR"},
            "Upscaling Method": {"newValue": 2, "valueName": "Nvidia DLSS"},
            "DLSS Frames": {"newValue": 0, "valueName": "1"},
            "UI Method": {"newValue": 0, "valueName": "Tablet"},
            "Player Name": {"valueName": "must-not-leak"},
        }
        with tempfile.TemporaryDirectory() as temp:
            save = Path(temp) / "Bodycam" / "Saved" / "SaveGames" / "GlobalUserSettings.sav"
            save.parent.mkdir(parents=True)
            import json

            save.write_bytes(b"GVAS\x00binary-prefix\x00" + json.dumps(settings).encode("utf-8") + b"\x00tail")
            with mock.patch.dict(environment.os.environ, {"LOCALAPPDATA": temp}):
                result = environment.bodycam_graphics_settings()
        self.assertEqual(
            result,
            {
                "fg_method": "AMD FSR",
                "upscaling_method": "Nvidia DLSS",
                "dlss_frames": "1",
                "ui_method": "Tablet",
            },
        )
        self.assertNotIn("Player Name", result)

    def test_bodycam_graphics_settings_skips_malformed_json_candidate(self) -> None:
        valid = (
            b'{"FG Method":{"valueName":"AMD FSR"},'
            b'"Upscaling Method":{"valueName":"Nvidia DLSS"},'
            b'"DLSS Frames":{"valueName":"1"},"UI Method":{"valueName":"Tablet"}}'
        )
        with tempfile.TemporaryDirectory() as temp:
            save = Path(temp) / "Bodycam" / "Saved" / "SaveGames" / "GlobalUserSettings.sav"
            save.parent.mkdir(parents=True)
            save.write_bytes(b'GVAS{"broken"\x00padding' + valid + b"\x00")
            with mock.patch.dict(environment.os.environ, {"LOCALAPPDATA": temp}):
                result = environment.bodycam_graphics_settings()
        self.assertEqual(result["fg_method"], "AMD FSR")

    def test_bodycam_graphics_settings_returns_empty_for_missing_corrupt_and_oversize(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            save = Path(temp) / "Bodycam" / "Saved" / "SaveGames" / "GlobalUserSettings.sav"
            with mock.patch.dict(environment.os.environ, {"LOCALAPPDATA": temp}):
                self.assertEqual(environment.bodycam_graphics_settings(), {})
                save.parent.mkdir(parents=True)
                save.write_bytes(b"GVAS not supported")
                self.assertEqual(environment.bodycam_graphics_settings(), {})
                save.write_bytes(b"x" * (environment.MAX_BODYCAM_SETTINGS_SIZE + 1))
                self.assertEqual(environment.bodycam_graphics_settings(), {})

    def test_gpu_info_parses_nvidia_smi(self) -> None:
        completed = subprocess.CompletedProcess([], 0, "NVIDIA GeForce RTX 3060 Ti, 8192, 8.6, 610.88\n", "")
        with mock.patch.object(environment.subprocess, "run", return_value=completed) as run:
            info = environment.gpu_info()
        self.assertEqual(info, {"name": "NVIDIA GeForce RTX 3060 Ti", "memory_mib": 8192, "compute_cap": "8.6", "driver": "610.88"})
        self.assertEqual(run.call_args.kwargs["timeout"], 6)
        self.assertEqual(run.call_args.kwargs["creationflags"], environment.CREATE_NO_WINDOW)

    def test_gpu_info_has_safe_fallback(self) -> None:
        with mock.patch.object(environment.subprocess, "run", side_effect=subprocess.TimeoutExpired("nvidia-smi", 6)):
            info = environment.gpu_info()
        self.assertIsNone(info["memory_mib"])
        self.assertIsNone(info["driver"])

    def test_ensure_game_closed_matches_exact_rendering_exe(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "Bodycam"
            exe = root / environment.BODYCAM_EXE
            exe.parent.mkdir(parents=True)
            exe.write_bytes(b"")
            game = Game(exe=exe, name="Bodycam", install_root=root)
            with mock.patch.object(environment, "_running_process_paths_native", return_value=[exe]):
                with self.assertRaisesRegex(PatcherError, "Игра запущена"):
                    environment.ensure_game_closed(game)

    def test_ensure_game_closed_does_not_match_same_filename_elsewhere(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "Bodycam"
            exe = root / environment.BODYCAM_EXE
            exe.parent.mkdir(parents=True)
            exe.write_bytes(b"")
            game = Game(exe=exe, name="Bodycam", install_root=root)
            other = Path(temp) / "Other" / exe.name
            with mock.patch.object(environment, "_running_process_paths_native", return_value=[other]):
                environment.ensure_game_closed(game)

    def test_ensure_game_closed_fails_closed_when_both_queries_fail(self) -> None:
        game = Game(Path("missing.exe"))
        with mock.patch.object(environment, "_running_process_paths_native", side_effect=OSError), mock.patch.object(
            environment, "_running_process_paths_powershell", side_effect=OSError
        ):
            with self.assertRaisesRegex(PatcherError, "безопасно проверить"):
                environment.ensure_game_closed(game)

    def test_ensure_game_closed_fails_for_unqueryable_matching_process_name(self) -> None:
        game = Game(Path("C:/Games/Bodycam/Bodycam-Win64-Shipping.exe"))
        with mock.patch.object(
            environment,
            "_running_process_paths_native",
            side_effect=environment._UnqueryableGameProcess("bodycam-win64-shipping.exe"),
        ), mock.patch.object(environment, "_running_process_paths_powershell") as fallback:
            with self.assertRaisesRegex(PatcherError, "не разрешает проверить"):
                environment.ensure_game_closed(game)
        fallback.assert_not_called()

    def test_detect_anticheat_only_uses_game_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "Game"
            marker = root / "EasyAntiCheat" / "EasyAntiCheat_EOS_Setup.exe"
            marker.parent.mkdir(parents=True)
            marker.write_bytes(b"")
            evidence = environment.detect_anticheat(Game(root / "Game.exe", install_root=root))
        self.assertTrue(any(item.startswith("Easy Anti-Cheat:") for item in evidence))
        self.assertFalse(any("service" in item.casefold() for item in evidence))


if __name__ == "__main__":
    unittest.main()
