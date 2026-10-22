# Local development helper. Release packages are built by GitHub Actions.
param([ValidateSet('amd64')][string]$Arch = 'amd64')
$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
$previousOS = $env:GOOS
$previousArch = $env:GOARCH
$previousCGO = $env:CGO_ENABLED
try {
    New-Item -ItemType Directory -Force bin | Out-Null
    $bpfDefines = @()
    if ($Arch -eq 'amd64') { $bpfDefines = @('-DSTACK_X86_64=1') }
    clang -O2 -g -target bpfel -Wall -Werror @bpfDefines -c bpf/tcp.c -o go/internal/device/collector/tcp_bpfel.o
    if ($LASTEXITCODE -ne 0) { throw 'BPF compilation failed' }
    $env:GOOS = 'linux'
    $env:GOARCH = $Arch
    $env:CGO_ENABLED = '0'
    clang -O2 -g -target bpfel -Wall -Werror -c bpf/frida.c -o go/internal/device/fridacapture/frida_bpfel.o
    if ($LASTEXITCODE -ne 0) { throw 'Frida BPF compilation failed' }
    clang -O2 -g -target bpfel -Wall -Werror -c bpf/fridastream.c -o go/internal/device/fridastream/fridastream_bpfel.o
    if ($LASTEXITCODE -ne 0) { throw 'Stream BPF compilation failed' }
    New-Item -ItemType Directory -Force bin/android-x86_64 | Out-Null
    go -C go build -trimpath -o ../bin/android-x86_64/ebpf-analyzer ./cmd/device
    if ($LASTEXITCODE -ne 0) { throw 'Device build failed' }
    $env:GOOS = $previousOS
    $env:GOARCH = $previousArch
    $hostOS = (go env GOHOSTOS).Trim()
    $hostArch = (go env GOHOSTARCH).Trim()
    $env:GOOS = $hostOS
    $env:GOARCH = $hostArch
    $monitorName = if ($hostOS -eq 'windows') { 'monitor.exe' } else { 'monitor' }
    go -C go build -trimpath -o "../bin/$monitorName" ./cmd/monitor
    if ($LASTEXITCODE -ne 0) { throw 'Monitor build failed' }
} finally {
    $env:GOOS = $previousOS
    $env:GOARCH = $previousArch
    $env:CGO_ENABLED = $previousCGO
    Pop-Location
}
