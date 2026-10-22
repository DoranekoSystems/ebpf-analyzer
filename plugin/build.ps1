param([string]$PacketProxyJar = "$PSScriptRoot/../../PacketProxy/build/libs/PacketProxy.jar")
$ErrorActionPreference = 'Stop'
$out = "$PSScriptRoot/build"
New-Item -ItemType Directory -Force "$out/classes" | Out-Null
javac -encoding UTF-8 --release 17 -cp $PacketProxyJar -d "$out/classes" "$PSScriptRoot/src/CommunicationOrigins.java" "$PSScriptRoot/src/DebuggerView.java" "$PSScriptRoot/src/SymbolLookup.java" "$PSScriptRoot/src/FridaLookup.java" "$PSScriptRoot/src/FridaView.java" "$PSScriptRoot/src/FridaStream.java" "$PSScriptRoot/src/AnalyzerSettings.java" "$PSScriptRoot/src/JavaSourceView.java" "$PSScriptRoot/src/ProcessBrowser.java" "$PSScriptRoot/src/UiLayout.java"
if ($LASTEXITCODE -ne 0) { throw 'Plugin compilation failed' }
jar --create --file "$out/CommunicationOrigins.jar" -C "$out/classes" ebpfproxy
if ($LASTEXITCODE -ne 0) { throw 'Plugin packaging failed' }
Write-Output "$out/CommunicationOrigins.jar"
