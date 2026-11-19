param(
    [string]$Version = "0.4.0"
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
$MsiOut = Join-Path $DistDir "Tachyon-$Version-x86_64.msi"

Copy-Item -LiteralPath $TargetExe -Destination $PlainExe -Force
Copy-Item -LiteralPath $TargetExe -Destination $PortableExe -Force
Compress-Archive -Path $PortableExe -DestinationPath $PortableZip -Force

# Удаляем устаревший артефакт самописного установщика при пересборке
$LegacySetup = Join-Path $DistDir "Tachyon-Setup-x86_64.exe"
if (Test-Path -LiteralPath $LegacySetup) {
    Remove-Item -LiteralPath $LegacySetup -Force
}

$WixDir = Join-Path $ProjectDir "wix"
$WixProj = Join-Path $WixDir "Tachyon.wixproj"
$IconPath = Join-Path $RootDir "src\app.ico"
$BannerBmp = Join-Path $WixDir "banner.bmp"
$DialogBmp = Join-Path $WixDir "dialog.bmp"

if ((-not (Test-Path -LiteralPath $BannerBmp)) -or (-not (Test-Path -LiteralPath $DialogBmp))) {
    $GenScript = Join-Path $WixDir "generate-branding.ps1"
    & powershell -ExecutionPolicy Bypass -File $GenScript -OutDir $WixDir
}

# Windows Installer требует числовую версию Major.Minor.Patch[.Build]
if ($Version -match '^(\d+\.\d+\.\d+)') {
    $MsiVersion = $Matches[1]
} else {
    $MsiVersion = "0.4.0"
}

Write-Host "==> Building Windows Installer MSI (v$MsiVersion)..."
$MsiBuildOut = Join-Path $WixDir "bin\Release\ru-RU"
dotnet build $WixProj -c Release `
    "-p:ProductVersion=$MsiVersion" `
    "-p:BinaryPath=$TargetExe" `
    "-p:IconPath=$IconPath" `
    "-p:BannerBmp=$BannerBmp" `
    "-p:DialogBmp=$DialogBmp"
if ($LASTEXITCODE -ne 0) {
    throw "dotnet build for MSI failed with exit code $LASTEXITCODE"
}

$BuiltMsi = Join-Path $MsiBuildOut "Tachyon.msi"
if (-not (Test-Path -LiteralPath $BuiltMsi)) {
    throw "Built MSI not found at $BuiltMsi"
}
Copy-Item -LiteralPath $BuiltMsi -Destination $MsiOut -Force

$MsiInfo = Get-Item -LiteralPath $MsiOut
if ($MsiInfo.Length -le 0) {
    throw "Packaged MSI is empty at $MsiOut"
}

# Проверяем метаданные собранного MSI через WindowsInstaller COM API
if ($PSVersionTable.PSEdition -eq "Core") {
    $env:TACHYON_MSI_OUT = $MsiOut
    $env:TACHYON_MSI_VER = $MsiVersion
    try {
        $PropsJson = & powershell.exe -NoProfile -NonInteractive -Command '$ErrorActionPreference="Stop"; $Wi=New-Object -ComObject WindowsInstaller.Installer; $Db=$Wi.OpenDatabase($env:TACHYON_MSI_OUT,0); $View=$Db.OpenView("SELECT Property, Value FROM Property WHERE Property=''ProductName'' OR Property=''ProductVersion'' OR Property=''UpgradeCode''"); $View.Execute(); $Props=@{}; while($Row=$View.Fetch()){ $Props[$Row.StringData(1)]=$Row.StringData(2) }; $View.Close(); if($Props["ProductName"] -ne "Tachyon" -or $Props["ProductVersion"] -ne $env:TACHYON_MSI_VER){ throw "Unexpected MSI metadata: ProductName=$($Props[''ProductName'']), ProductVersion=$($Props[''ProductVersion''])" }; $Props | ConvertTo-Json -Compress'
        if ($LASTEXITCODE -ne 0) {
            throw "MSI metadata check failed in powershell.exe with exit code $LASTEXITCODE"
        }
        $Parsed = ($PropsJson | Out-String) | ConvertFrom-Json
        $Props = @{
            "ProductName"    = $Parsed.ProductName
            "ProductVersion" = $Parsed.ProductVersion
            "UpgradeCode"    = $Parsed.UpgradeCode
        }
    } finally {
        Remove-Item Env:TACHYON_MSI_OUT, Env:TACHYON_MSI_VER -ErrorAction SilentlyContinue
    }
} else {
    $Wi = New-Object -ComObject WindowsInstaller.Installer
    $Db = $Wi.OpenDatabase($MsiOut, 0)
    $View = $Db.OpenView("SELECT Property, Value FROM Property WHERE Property='ProductName' OR Property='ProductVersion' OR Property='UpgradeCode'")
    $View.Execute()
    $Props = @{}
    while ($Row = $View.Fetch()) {
        $Props[$Row.StringData(1)] = $Row.StringData(2)
    }
    $View.Close()
}
if ($Props["ProductName"] -ne "Tachyon" -or $Props["ProductVersion"] -ne $MsiVersion) {
    throw "Unexpected MSI metadata: ProductName=$($Props['ProductName']), ProductVersion=$($Props['ProductVersion'])"
}

Write-Host "==> Packaged Windows artifacts in ${DistDir}:"
Write-Host "    - $PlainExe"
Write-Host "    - $PortableExe"
Write-Host "    - $PortableZip"
Write-Host "    - $MsiOut ($($MsiInfo.Length) bytes, ProductVersion=$($Props['ProductVersion']), UpgradeCode=$($Props['UpgradeCode']))"
