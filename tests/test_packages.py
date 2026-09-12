from __future__ import annotations

import hashlib
import io
import json
import shutil
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from patcher_app import packages
from patcher_app.models import Bundle, PatcherError


REPO = Path(__file__).parents[1]


class Response(io.BytesIO):
    def __init__(self, data: bytes, *, declared_length: int | None = None, final_url: str | None = None):
        super().__init__(data)
        length = len(data) if declared_length is None else declared_length
        self.headers = {"Content-Length": str(length)}
        self._final_url = final_url

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def geturl(self):
        return self._final_url or "https://api.github.com/response"


def network_for(files: dict[str, bytes], revision: str, interrupt: str | None = None):
    tree = [
        {"path": path, "type": "blob", "sha": packages._git_blob_sha1(data)}
        for path, data in files.items()
    ]
    commit_data = json.dumps({"sha": revision}).encode()
    tree_data = json.dumps({"truncated": False, "tree": tree}).encode()

    def urlopen(request, timeout):
        url = request.full_url
        if url.endswith("/commits/main"):
            return Response(commit_data, final_url=url)
        if "/git/trees/" in url:
            return Response(tree_data, final_url=url)
        remote_path = url.split(f"/{revision}/", 1)[1]
        if remote_path == interrupt:
            raise urllib.error.URLError("connection reset")
        return Response(files[remote_path], final_url=url)

    return urlopen


class PackageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.bundled = packages.create_bundled_payload(REPO, self.root / "bundled-payload")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def upstream_files(self, changed_ini: bool = False) -> dict[str, bytes]:
        result = {
            remote: (self.bundled.root / local).read_bytes()
            for local, remote in packages.REMOTE_PATHS.items()
        }
        if changed_ini:
            result["dlssg_sm86.ini"] = result["dlssg_sm86.ini"].replace(b"Level=1", b"Level=2")
        result[packages.README_PATH] = b"# DLSSG Native 0.2.5\n"
        return result

    def test_create_load_and_validate_flat_payload(self) -> None:
        self.assertEqual(self.bundled.label, "Native 0.2.4")
        self.assertEqual(set(self.bundled.files), set(packages.REQUIRED_FILES))
        self.assertEqual(
            {path.name for path in self.bundled.root.iterdir()},
            {*packages.REQUIRED_FILES, "manifest.json"},
        )
        loaded = packages.load_bundle(self.bundled.root)
        packages.validate_bundle(loaded)
        self.assertEqual(loaded, self.bundled)

    def test_repeated_create_is_noop_for_matching_payload(self) -> None:
        manifest = self.bundled.root / packages.MANIFEST_NAME
        before = manifest.stat().st_mtime_ns
        with mock.patch.object(packages.shutil, "rmtree") as remove:
            again = packages.create_bundled_payload(REPO, self.bundled.root)
        self.assertEqual(again, self.bundled)
        self.assertEqual(manifest.stat().st_mtime_ns, before)
        remove.assert_not_called()

    def test_failed_replacement_restores_previous_payload(self) -> None:
        manifest = self.bundled.root / packages.MANIFEST_NAME
        old = json.loads(manifest.read_text(encoding="utf-8"))
        old["revision"] = "e" * 40
        manifest.write_text(json.dumps(old), encoding="utf-8")
        before = {path.name: path.read_bytes() for path in self.bundled.root.iterdir()}
        real_replace = packages.os.replace

        def fail_publish(source, destination):
            source_path = Path(source)
            destination_path = Path(destination)
            if (source_path.name.startswith(".bundled-payload-")
                    and "-previous-" not in source_path.name
                    and destination_path == self.bundled.root):
                raise PermissionError("simulated publish failure")
            return real_replace(source, destination)

        with mock.patch.object(packages.os, "replace", side_effect=fail_publish):
            with self.assertRaisesRegex(PatcherError, "Не удалось создать встроенный пакет"):
                packages.create_bundled_payload(REPO, self.bundled.root)
        after = {path.name: path.read_bytes() for path in self.bundled.root.iterdir()}
        self.assertEqual(after, before)

    def test_payload_supports_cyrillic_and_spaces(self) -> None:
        destination = self.root / "Данные патчера" / "bundled-payload"
        bundle = packages.create_bundled_payload(REPO, destination)
        packages.validate_bundle(bundle)
        self.assertEqual(bundle.root, destination.resolve())

    def test_unsafe_payload_destination_is_rejected(self) -> None:
        with self.assertRaisesRegex(PatcherError, "должен находиться в build"):
            packages.create_bundled_payload(REPO, REPO)
        with self.assertRaisesRegex(PatcherError, "должен находиться в build"):
            packages.create_bundled_payload(REPO, self.root / "arbitrary")

    def test_pinned_baseline_rejects_changed_source(self) -> None:
        fake_repo = self.root / "source"
        fake_repo.mkdir()
        for remote in packages.REMOTE_PATHS.values():
            source = REPO / remote
            target = fake_repo / remote
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        (fake_repo / "dlssg_sm86.ini").write_text("changed", encoding="utf-8")
        with self.assertRaisesRegex(PatcherError, "закреплённому Native 0.2.4"):
            packages.create_bundled_payload(fake_repo, self.root / "other" / "bundled-payload")

    def test_corruption_is_detected_and_not_masked_by_fallback(self) -> None:
        cache = self.root / "data" / "cache"
        target = cache / self.bundled.revision
        shutil.copytree(self.bundled.root, target)
        (target / "version.dll").write_bytes(b"corrupt")
        (cache / "current.json").write_text(json.dumps({"revision": self.bundled.revision}), encoding="utf-8")
        with self.assertRaisesRegex(PatcherError, "контрольная сумма"):
            packages.latest_cached(self.root / "data", self.bundled)

    def test_ini_unknown_key_is_rejected(self) -> None:
        ini = self.bundled.root / "dlssg_sm86.ini"
        ini.write_text(ini.read_text(encoding="utf-8") + "Unknown=1\n", encoding="utf-8")
        files = dict(self.bundled.files)
        files[ini.name] = hashlib.sha256(ini.read_bytes()).hexdigest()
        changed = Bundle(self.bundled.root, self.bundled.revision, self.bundled.label, files)
        with self.assertRaisesRegex(PatcherError, "неверный набор параметров"):
            packages.validate_bundle(changed)

    def test_update_is_pinned_validated_and_atomically_published(self) -> None:
        revision = "a" * 40
        opener = network_for(self.upstream_files(changed_ini=True), revision)
        with mock.patch.object(packages.urllib.request, "urlopen", opener):
            updated = packages.check_for_update(self.root / "data", self.bundled)
        self.assertEqual(updated.revision, revision)
        self.assertEqual(updated.label, "Native 0.2.5")
        self.assertEqual(packages.latest_cached(self.root / "data", self.bundled), updated)
        pointer = json.loads((self.root / "data/cache/current.json").read_text())
        self.assertEqual(pointer["revision"], revision)
        packages.validate_bundle(updated)

    def test_readme_only_change_does_not_publish_update(self) -> None:
        revision = "b" * 40
        opener = network_for(self.upstream_files(), revision)
        with mock.patch.object(packages.urllib.request, "urlopen", opener):
            result = packages.check_for_update(self.root / "data", self.bundled)
        self.assertEqual(result, self.bundled)
        self.assertFalse((self.root / "data/cache/current.json").exists())
        self.assertFalse((self.root / f"data/cache/{revision}").exists())

    def test_interrupted_download_preserves_existing_cache(self) -> None:
        data_dir = self.root / "data"
        cache = data_dir / "cache"
        old = cache / self.bundled.revision
        shutil.copytree(self.bundled.root, old)
        pointer = cache / "current.json"
        pointer.write_text(json.dumps({"revision": self.bundled.revision}), encoding="utf-8")
        before = pointer.read_bytes()
        revision = "c" * 40
        opener = network_for(self.upstream_files(changed_ini=True), revision, "altnative/winhttp.dll")
        with mock.patch.object(packages.urllib.request, "urlopen", opener), mock.patch.object(packages.time, "sleep"):
            with self.assertRaisesRegex(PatcherError, "Не удалось получить данные GitHub"):
                packages.check_for_update(data_dir, self.bundled)
        self.assertEqual(pointer.read_bytes(), before)
        self.assertEqual(packages.latest_cached(data_dir, self.bundled).revision, self.bundled.revision)
        self.assertFalse((cache / revision).exists())

    def test_git_blob_mismatch_rejects_update_without_pointer(self) -> None:
        revision = "d" * 40
        opener = network_for(self.upstream_files(changed_ini=True), revision)

        def corrupting_opener(request, timeout):
            response = opener(request, timeout)
            if request.full_url.endswith("/dlssg_sm86.ini"):
                return Response(response.read() + b"\n", final_url=request.full_url)
            return response

        with mock.patch.object(packages.urllib.request, "urlopen", corrupting_opener):
            with self.assertRaisesRegex(PatcherError, "Git blob SHA-1"):
                packages.check_for_update(self.root / "data", self.bundled)
        self.assertFalse((self.root / "data/cache/current.json").exists())

    def test_incomplete_content_length_is_rejected(self) -> None:
        response = Response(b"short", declared_length=100)
        with self.assertRaisesRegex(PatcherError, "Content-Length"):
            packages._read_limited(response, 1000)

    def test_cross_host_redirect_is_rejected(self) -> None:
        response = Response(b"{}", final_url="https://example.invalid/payload")
        with mock.patch.object(packages, "_open_with_retries", return_value=response):
            with self.assertRaisesRegex(PatcherError, "недоверенный адрес"):
                packages._fetch("https://api.github.com/repos/test", 1024)

    def test_offline_returns_error_without_changing_cache(self) -> None:
        def offline(*args, **kwargs):
            raise urllib.error.URLError("offline")

        with mock.patch.object(packages.urllib.request, "urlopen", offline), mock.patch.object(packages.time, "sleep"):
            with self.assertRaisesRegex(PatcherError, "Не удалось получить данные GitHub"):
                packages.check_for_update(self.root / "data", self.bundled)
        self.assertEqual(packages.latest_cached(self.root / "data", self.bundled), self.bundled)


if __name__ == "__main__":
    unittest.main()
