#!/usr/bin/env python3
"""Scan source with the SDK levels Gradle adds to the merged manifest.

MobSF defaults to API 26 when a source manifest lacks uses-sdk. AGP owns
these values in Qubee, so scan a temporary copy with the actual literals.
Never change the build inputs or suppress task-hijacking rules.
"""
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

ANDROID = "http://schemas.android.com/apk/res/android"

def prepare_source_tree(workspace: Path, stage: Path) -> None:
    gradle = (workspace / "app/build.gradle").read_text()
    levels = {}
    for name in ("minSdk", "targetSdk"):
        matches = re.findall(r"^\s*" + name + r"\s+(\d+)\s*$", gradle, re.MULTILINE)
        if len(matches) != 1:
            raise ValueError(f"Expected one literal {name}; update scanner SDK extraction")
        levels[name] = matches[0]
    source = stage / "app/src/main"
    shutil.copytree(workspace / "app/src/main", source)
    manifest = source / "AndroidManifest.xml"
    ET.register_namespace("android", ANDROID)
    ET.register_namespace("tools", "http://schemas.android.com/tools")
    tree = ET.parse(manifest)
    root = tree.getroot()
    sdk = root.find("uses-sdk")
    if sdk is None:
        sdk = ET.Element("uses-sdk")
        root.insert(0, sdk)
    sdk.set(f"{{{ANDROID}}}minSdkVersion", levels["minSdk"])
    sdk.set(f"{{{ANDROID}}}targetSdkVersion", levels["targetSdk"])
    tree.write(manifest, encoding="utf-8", xml_declaration=True)

def main() -> int:
    workspace = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="qubee-mobsf-") as temporary:
        stage = Path(temporary)
        prepare_source_tree(workspace, stage)
        return subprocess.run(
            ["mobsfscan", "app/src/main", "--type", "android", "--sarif",
             "--output", str(workspace / "results.sarif")],
            cwd=stage, check=False,
        ).returncode

if __name__ == "__main__":
    raise SystemExit(main())
