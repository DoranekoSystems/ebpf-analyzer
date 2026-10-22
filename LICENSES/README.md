# License scope

Unless a file carries a different license notice, the original source code and
documentation in this repository are licensed under the Apache License, Version 2.0.
See the root `LICENSE` file for the complete terms.

The following Linux eBPF programs retain their GPL license and are covered by
`GPL-2.0-only.txt` in this directory:

- `bpf/tcp.c`
- `bpf/frida.c`
- `bpf/fridastream.c`

Their generated BPF object files retain the same license, including when embedded
in a Go executable. The root Apache license does not relicense those objects.

Third-party components retain their respective licenses. PacketProxy, Go modules,
Frida, and the Java bridge supplied by frida-tools are not relicensed by this
repository. Preserve their applicable notices when distributing those components.

Desktop distribution ZIPs include `LICENSES/third-party-go/`. The build reads the
actual dependency versions and checksums from both shipped Go binaries, copies
upstream license/notice files from checksum-verified modules, and includes the Go
toolchain license. Its `manifest.json` records the modules, binaries, and files.
Packaging fails if a module's license is missing or the binaries use a different
Go toolchain than the packaging environment. Rebuild both binaries together.

References:

- https://www.kernel.org/doc/html/latest/bpf/bpf_licensing.html
- https://www.apache.org/licenses/LICENSE-2.0
