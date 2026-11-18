param(
    [string]$Version = "0.3.9"
)

$ErrorActionPreference = "Stop"

$Version = $Version.TrimStart('v')
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptDir
$RootDir = Split-Path -Parent $ProjectDir
$ManifestPath = Join-Path $ProjectDir "Cargo.toml"
$TargetExe = Join-Path $ProjectDir "target\release\tachyon.exe"
$DistDir = Join-Path $RootDir "dist"

Write-Host "==> Building tachyon-desktop (release, v$Version)..."
cargo build --release --manifest-path $ManifestPath
if ($LASTEXITCODE -ne 0) {
    throw "cargo build --release failed with exit code $LASTEXITCODE"
}
if (-not (Test-Path -LiteralPath $TargetExe)) {
    throw "Release binary not found at $TargetExe"
}

New-Item -ItemType Directory -Force -Path $DistDir | Out-Null

$PlainExe = Join-Path $DistDir "Tachyon.exe"
$PortableExe = Join-Path $DistDir "Tachyon-windows-x86_64.exe"
$PortableZip = Join-Path $DistDir "Tachyon-windows-x86_64.zip"
$SetupExe = Join-Path $DistDir "Tachyon-Setup-x86_64.exe"

Copy-Item -LiteralPath $TargetExe -Destination $PlainExe -Force
Copy-Item -LiteralPath $TargetExe -Destination $PortableExe -Force
Compress-Archive -Path $PortableExe -DestinationPath $PortableZip -Force

# Формируем одиночный установщик дописыванием 8-байтового маркера TCHYINST в конец PE-файла
Copy-Item -LiteralPath $PortableExe -Destination $SetupExe -Force
$MagicBytes = [System.Text.Encoding]::ASCII.GetBytes("TCHYINST")
$Stream = [System.IO.File]::Open($SetupExe, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write)
try {
    $Stream.Write($MagicBytes, 0, $MagicBytes.Length)
} finally {
    $Stream.Dispose()
}

# Проверяем наличие маркера TCHYINST в хвосте установщика
$VerifyStream = [System.IO.File]::OpenRead($SetupExe)
try {
    if ($VerifyStream.Length -lt $MagicBytes.Length) {
        throw "Setup executable is unexpectedly small"
    }
    $VerifyStream.Seek(-$MagicBytes.Length, [System.IO.SeekOrigin]::End) | Out-Null
    $Tail = New-Object byte[] $MagicBytes.Length
    $Read = $VerifyStream.Read($Tail, 0, $Tail.Length)
    $TailText = [System.Text.Encoding]::ASCII.GetString($Tail, 0, $Read)
    if ($TailText -ne "TCHYINST") {
        throw "Failed to verify TCHYINST trailer on $SetupExe"
    }
} finally {
    $VerifyStream.Dispose()
}

Write-Host "==> Packaged Windows artifacts in ${DistDir}:"
Write-Host "    - $PlainExe"
Write-Host "    - $PortableExe"
Write-Host "    - $PortableZip"
Write-Host "    - $SetupExe"
