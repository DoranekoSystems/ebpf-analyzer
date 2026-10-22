#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p bin/android-x86_64
clang -O2 -g -target bpfel -Wall -Werror -DSTACK_X86_64=1 -c bpf/tcp.c -o go/internal/device/collector/tcp_bpfel.o
clang -O2 -g -target bpfel -Wall -Werror -c bpf/frida.c -o go/internal/device/fridacapture/frida_bpfel.o
clang -O2 -g -target bpfel -Wall -Werror -c bpf/fridastream.c -o go/internal/device/fridastream/fridastream_bpfel.o
# Static Linux binaries run on the rooted Android x86_64 target without bionic/NDK linking.
export GOOS=linux GOARCH=amd64 CGO_ENABLED=0
go -C go build -trimpath -o ../bin/android-x86_64/ebpf-analyzer ./cmd/device
