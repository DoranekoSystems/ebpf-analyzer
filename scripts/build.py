"""Build the PacketProxy plugin and assemble a desktop distribution."""

import argparse
import os
import pathlib
import shutil
import subprocess
from go_notices import collect as collect_go_notices

ROOT = pathlib.Path(__file__).resolve().parents[1]


def run(*args, **kwargs):
    subprocess.run(args, cwd=ROOT, check=True, **kwargs)


def plugin(jar):
    output = ROOT / "plugin/build"
    classes = output / "classes"
    classes.mkdir(parents=True, exist_ok=True)
    sources = sorted(str(p) for p in (ROOT / "plugin/src").glob("*.java"))
    run(
        "javac",
        "-encoding",
        "UTF-8",
        "--release",
        "17",
        "-cp",
        str(jar),
        "-d",
        str(classes),
        *sources,
    )
    artifact = output / "CommunicationOrigins.jar"
    run("jar", "--create", "--file", str(artifact), "-C", str(classes), "ebpfproxy")
    return artifact


def package(args):
    jar = plugin(pathlib.Path(args.packetproxy_jar).resolve())
    output = pathlib.Path(args.output_dir).resolve() / f"ebpf-analyzer-{args.os}-{args.arch}"
    if output.exists():
        raise RuntimeError(f"Output already exists: {output}; choose a clean workspace")
    output.mkdir(parents=True)
    env = dict(os.environ, GOOS=args.os, GOARCH=args.arch, CGO_ENABLED="0")
    monitor = output / ("monitor.exe" if args.os == "windows" else "monitor")
    run(
        "go",
        "-C",
        str(ROOT / "go"),
        "build",
        "-trimpath",
        "-o",
        str(monitor),
        "./cmd/monitor",
        env=env,
    )
    (output / "plugin").mkdir()
    shutil.copy2(jar, output / "plugin" / jar.name)
    device = pathlib.Path(args.device_dir).resolve()
    for name in ("ebpf-analyzer",):
        if not (device / name).is_file():
            raise FileNotFoundError(device / name)
    (output / "android-x86_64").mkdir()
    shutil.copy2(device / "ebpf-analyzer", output / "android-x86_64/ebpf-analyzer")
    for name in ("ebpf-analyzer",):
        (output / "android-x86_64" / name).chmod(0o755)
    (output / "frida").mkdir()
    for name in ("agent.js", "bridge.py", "stream.py"):
        shutil.copy2(ROOT / "frida" / name, output / "frida" / name)
    for name in ("README.md", "LICENSE"):
        shutil.copy2(ROOT / name, output / name)
    shutil.copytree(ROOT / "LICENSES", output / "LICENSES")
    collect_go_notices(ROOT, [monitor, output / "android-x86_64/ebpf-analyzer"],
                       output / "LICENSES/third-party-go")
    (output / "docs").mkdir()
    shutil.copy2(ROOT / "docs/demo.gif", output / "docs/demo.gif")
    # Include the BPF sources corresponding to the embedded GPL objects.
    shutil.copytree(ROOT / "bpf", output / "bpf")
    if args.os != "windows":
        monitor.chmod(0o755)
    archive = shutil.make_archive(str(output), "zip", root_dir=output.parent, base_dir=output.name)
    print(archive)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packetproxy-jar", required=True)
    parser.add_argument("--output-dir", default="dist")
    parser.add_argument("--device-dir", default="bin/android-x86_64")
    parser.add_argument("--os", choices=["windows", "linux", "darwin"], required=True)
    parser.add_argument("--arch", choices=["amd64", "arm64"], required=True)
    package(parser.parse_args())
