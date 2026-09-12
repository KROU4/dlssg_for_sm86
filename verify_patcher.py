"""Distribution smoke tests; never installs or changes a game."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from PyInstaller.archive.readers import CArchiveReader


def verify(executable: Path) -> dict:
    root = executable.parent
    artifacts = root / "test-artifacts"
    artifacts.mkdir(exist_ok=True)
    archive = CArchiveReader(str(executable))
    proxies = {"version.dll", "winmm.dll", "winhttp.dll", "dxgi.dll", "dinput8.dll"}
    payload_names = set()
    manifest_key = next(name for name in archive.toc if name.replace("\\", "/") == "payload/manifest.json")
    manifest = json.loads(archive.extract(manifest_key).decode("utf-8"))
    for destination, entry in archive.toc.items():
        normalized = destination.replace("\\", "/")
        if Path(normalized).name.lower() in proxies:
            # PyInstaller maps executable-permission DATA to 'b' even on Windows.
            # The important boundary is the payload subdirectory plus exact bytes,
            # not the archive's executable-permission flag.
            if not normalized.startswith("payload/") or entry[-1] not in {"x", "b"}:
                raise RuntimeError(f"Proxy became executable dependency: {destination}: {entry[-1]}")
            if hashlib.sha256(archive.extract(destination)).hexdigest() != manifest["files"][Path(normalized).name]:
                raise RuntimeError(f"Embedded proxy was modified: {destination}")
            payload_names.add(Path(normalized).name.lower())
    if payload_names != proxies:
        raise RuntimeError("Incomplete embedded proxy payload")
    results = []
    standalone = artifacts / "Переносной EXE"
    standalone.mkdir(exist_ok=True)
    shutil.copy2(executable, standalone / executable.name)
    for label, folder in (("root", root), ("standalone", standalone)):
        report_path = artifacts / f"distribution-{label}.json"
        report_path.unlink(missing_ok=True)
        env = dict(os.environ)
        env["PATH"] = os.pathsep.join(str(Path(os.environ["SystemRoot"]) / p) for p in ("System32", "", "System32/Wbem"))
        env.pop("PYTHONPATH", None)
        env["PYTHONHOME"] = str(artifacts / "python-not-installed")
        env.pop("QT_PLUGIN_PATH", None)
        command = [str(folder / executable.name), "--self-test", "--no-network", "--report", str(report_path), "--screenshot", str(artifacts / f"distribution-{label}.png")]
        completed = subprocess.run(command, cwd=folder, env=env, timeout=90, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if completed.returncode or not report_path.is_file():
            raise RuntimeError(f"{label} self-test failed: exit {completed.returncode}")
        report = json.loads(report_path.read_text(encoding="utf-8"))
        if not report.get("ok") or not report.get("runtime", {}).get("frozen"):
            raise RuntimeError(f"{label} self-test did not confirm frozen runtime")
        system_dir = Path(os.environ["SystemRoot"]) / "System32"
        for module in report.get("proxy_named_modules", []):
            if Path(module).resolve().parent != system_dir.resolve():
                raise RuntimeError(f"{label} loaded non-system proxy: {module}")
        results.append({"scenario": label, "ok": True, "report": str(report_path)})
    summary = {"ok": True, "exe": str(executable), "size_bytes": executable.stat().st_size, "sha256": hashlib.sha256(executable.read_bytes()).hexdigest(), "embedded_proxies_as_data": sorted(payload_names), "smoke_tests": results}
    (artifacts / "distribution-verification.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    return summary


if __name__ == "__main__":
    if sys.stdout is not None:
        sys.stdout.reconfigure(encoding="utf-8")
    print(json.dumps(verify(Path(__file__).resolve().parent / "DLSSG-Patcher.exe"), ensure_ascii=False, indent=2))
