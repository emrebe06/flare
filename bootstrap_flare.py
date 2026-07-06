#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Create a clean local environment and install Flare dependencies."""

from __future__ import annotations

import platform
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENV = ROOT / ".venv"


def run(cmd: list[str]) -> None:
    print("+", " ".join(cmd))
    subprocess.run(cmd, cwd=ROOT, check=True)


def venv_python() -> Path:
    if platform.system().lower().startswith("win"):
        return VENV / "Scripts" / "python.exe"
    return VENV / "bin" / "python"


def main() -> int:
    if not VENV.exists():
        run([sys.executable, "-m", "venv", str(VENV)])

    py = venv_python()
    run([str(py), "-m", "pip", "install", "--upgrade", "pip"])
    run([str(py), "-m", "pip", "install", "-r", str(ROOT / "requirements.txt")])

    expected = [
        ROOT / "native" / "libstarfall_core.dll",
        ROOT / "native" / "libstarfall_core.so",
        ROOT / "native" / "libstarfall_core.dylib",
        ROOT / "data" / "flame_probability.xmll",
    ]
    missing = [str(path.relative_to(ROOT)) for path in expected if not path.exists()]
    if missing:
        raise SystemExit("Missing packaged files: " + ", ".join(missing))

    print("Flare setup completed.")
    print("Start GUI with:")
    print(f"  {py} run_flare.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
