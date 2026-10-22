"""Collect upstream notice files for the modules actually linked into shipped binaries."""

import json
import pathlib
import shutil
import subprocess


def collect(root, binaries, destination):
    def go(*args):
        return subprocess.check_output(
            ["go", "-C", str(root / "go"), *args], text=True, encoding="utf-8"
        )

    modules = {}
    versions = set()
    for binary in binaries:
        lines = go("version", "-m", str(binary)).splitlines()
        versions.add(lines[0].rsplit(": ", 1)[1])
        for line in lines[1:]:
            fields = line.split()
            if fields and fields[0] == "=>":
                raise RuntimeError("Resolve replaced Go modules explicitly before distributing")
            if fields and fields[0] == "dep":
                key = (fields[1], fields[2])
                modules.setdefault(key, {"path": fields[1], "version": fields[2],
                                         "sum": fields[3] if len(fields) > 3 else "",
                                         "binaries": []})["binaries"].append(binary.name)

    env = json.loads(go("env", "-json", "GOROOT", "GOVERSION"))
    if versions != {env["GOVERSION"]}:
        raise RuntimeError("Rebuild all shipped Go binaries with the configured toolchain before collecting notices")
    destination.mkdir(parents=True, exist_ok=True)
    toolchain = destination / "go"
    toolchain.mkdir()
    for name in ("LICENSE", "PATENTS"):
        source = pathlib.Path(env["GOROOT"]) / name
        if source.is_file():
            shutil.copy2(source, toolchain / name)
    if not (toolchain / "LICENSE").is_file():
        raise RuntimeError("Go toolchain LICENSE missing")

    notice_names = {"LICENSE", "LICENCE", "NOTICE", "COPYING", "COPYRIGHT", "PATENTS", "AUTHORS"}
    for (path, version), record in sorted(modules.items()):
        module = json.loads(go("mod", "download", "-json", path + "@" + version))
        if module.get("Sum", "") != record["sum"]:
            raise RuntimeError("Module checksum differs from the shipped binary: " + path)
        source = pathlib.Path(module["Dir"])
        target = destination / (path + "@" + version)
        files = []
        for item in sorted(source.rglob("*")):
            if not item.is_file():
                continue
            name = item.name.upper()
            if not any(name == base or name.startswith(base + ".") or name.startswith(base + "-")
                       for base in notice_names):
                continue
            relative = item.relative_to(source)
            output = target / relative
            output.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, output)
            # Downloaded module cache files can be read-only on Windows.
            output.chmod(0o644)
            files.append(relative.as_posix())
        if not any(pathlib.PurePosixPath(name).name.upper().startswith(("LICENSE", "LICENCE", "COPYING")) for name in files):
            raise RuntimeError("No upstream license found for " + path)
        record["noticeFiles"] = files

    manifest = {"goVersion": env["GOVERSION"], "modules": list(modules.values())}
    (destination / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    lines = ["# Go dependency notices", "", "Generated from the shipped binaries' Go build metadata.",
             "Upstream LICENSE/NOTICE and related files are copied unchanged from checksum-verified modules.",
             "The Go toolchain license is in `go/`. These files retain their upstream license terms.", "",
             "| Module | Version | Included in |", "| --- | --- | --- |"]
    for (path, version), record in sorted(modules.items()):
        lines.append(f"| {path} | {version} | {', '.join(record['binaries'])} |")
    lines += ["", "See `manifest.json` for checksums and the list of included notice files.", ""]
    (destination / "README.md").write_text("\n".join(lines), encoding="utf-8")
