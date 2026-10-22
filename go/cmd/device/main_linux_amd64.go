//go:build linux && amd64

// ebpf-analyzer is the shared Android x86_64 device executable.
package main

import (
	"fmt"
	"os"

	"github.com/DoranekoSystems/ebpf-analyzer/internal/device/collector"
	"github.com/DoranekoSystems/ebpf-analyzer/internal/device/fridacapture"
	"github.com/DoranekoSystems/ebpf-analyzer/internal/device/fridastream"
	"github.com/DoranekoSystems/ebpf-analyzer/internal/device/symbols"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	command := os.Args[1]
	os.Args = append([]string{os.Args[0] + " " + command}, os.Args[2:]...)
	switch command {
	case "monitor":
		collector.Main()
	case "symbols":
		symbols.Main()
	case "frida-capture":
		fridacapture.Main()
	case "frida-stream":
		fridastream.Main()
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "Usage: ebpf-analyzer <monitor|symbols|frida-capture|frida-stream> [arguments]")
}
