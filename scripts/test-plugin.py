"""Run device-independent Swing tests on the desktop build."""

import argparse
import os
import pathlib
import subprocess

root = pathlib.Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--packetproxy-jar", required=True)
args = parser.parse_args()
jar = root / "plugin/build/CommunicationOrigins.jar"
tests = root / "plugin/build/tests"
tests.mkdir(parents=True, exist_ok=True)
cp = os.pathsep.join([str(jar), str(pathlib.Path(args.packetproxy_jar).resolve())])
sources = ["TableRefreshTest.java", "DebuggerViewTest.java", "PacketSelectionTest.java", "JavaSourceViewTest.java", "ProcessBrowserTest.java"]
subprocess.run(
    [
        "javac",
        "-encoding",
        "UTF-8",
        "--release",
        "17",
        "-cp",
        cp,
        "-d",
        str(tests),
        *[str(root / "plugin/test" / s) for s in sources],
    ],
    check=True,
    cwd=root,
)
for name in ["ebpfproxy.TableRefreshTest", "DebuggerViewTest", "PacketSelectionTest", "ebpfproxy.JavaSourceViewTest", "ebpfproxy.ProcessBrowserTest"]:
    extra = [str(tests / "debugger.png")] if name == "DebuggerViewTest" else []
    subprocess.run(
        [
            "java",
            "-Djava.awt.headless=true",
            "-cp",
            str(tests) + os.pathsep + cp,
            name,
            str(jar),
            *extra,
        ],
        check=True,
        cwd=root,
    )
