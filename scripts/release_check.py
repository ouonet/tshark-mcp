#!/usr/bin/env python3
"""Run pre-release checks for this project.

Checks performed:
1. Run test suite.
2. Build sdist and wheel.
3. Validate distribution metadata with twine check via uvx.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from glob import glob
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIST = ROOT / "dist"


def run(cmd: list[str], step: str) -> None:
    print(f"\n[release-check] {step}")
    print("[release-check] $", " ".join(cmd))
    subprocess.run(cmd, cwd=ROOT, check=True)


def ensure_uv() -> str:
    """Return uv executable path if available, else raise an error."""
    uv = shutil.which("uv")
    if not uv:
        raise RuntimeError("uv is not installed or not on PATH")
    return uv


def detect_uvx_prefix(uv: str) -> list[str]:
    """Detect how to run ephemeral tools across uv versions.

    Supported forms:
    - uv x <tool>
    - uv tool run <tool>
    - uvx <tool>
    """
    probe_x = subprocess.run(
        [uv, "help", "x"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if probe_x.returncode == 0:
        return [uv, "x"]

    probe_tool_run = subprocess.run(
        [uv, "help", "tool"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if probe_tool_run.returncode == 0:
        return [uv, "tool", "run"]

    uvx = shutil.which("uvx")
    if uvx:
        return [uvx]

    raise RuntimeError("No supported uv ephemeral tool runner found (uv x / uv tool run / uvx)")


def main() -> int:
    try:
        uv = ensure_uv()
        uvx_prefix = detect_uvx_prefix(uv)
        run([uv, "run", "python", "-m", "pytest", "test_server.py", "-q"], "Run tests")

        if DIST.exists():
            shutil.rmtree(DIST)

        run([uv, "build"], "Build source and wheel distributions")

        dist_files = sorted(glob(str(DIST / "*")))
        if not dist_files:
            print("[release-check] No distribution files were produced.")
            return 1

        run([*uvx_prefix, "twine", "check", *dist_files], "Validate distributions")

        print("\n[release-check] SUCCESS: all release checks passed.")
        return 0
    except RuntimeError as exc:
        print(f"\n[release-check] FAILED: {exc}")
        return 1
    except subprocess.CalledProcessError as exc:
        print(f"\n[release-check] FAILED at step with exit code {exc.returncode}.")
        return exc.returncode or 1


if __name__ == "__main__":
    raise SystemExit(main())
