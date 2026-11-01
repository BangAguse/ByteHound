$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    throw "Go 1.22 or newer is required."
}
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    throw "Rust/Cargo is required."
}

cargo build --manifest-path scanner/Cargo.toml --release
if ($LASTEXITCODE -ne 0) { throw "Rust scanner build failed." }

$BuildDir = Join-Path $Root "bin"
New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null
$Dll = Join-Path $Root "scanner\target\release\bytehound_scanner.dll"
if (-not (Test-Path $Dll)) { throw "Expected Rust DLL was not produced: $Dll" }
Copy-Item $Dll (Join-Path $BuildDir "bytehound_scanner.dll") -Force
go build -o (Join-Path $BuildDir "bytehound.exe") .
if ($LASTEXITCODE -ne 0) { throw "Go CLI build failed." }

$InstallDir = Join-Path $env:LOCALAPPDATA "ByteHound\bin"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item (Join-Path $BuildDir "bytehound.exe") (Join-Path $InstallDir "bytehound.exe") -Force
Copy-Item (Join-Path $BuildDir "bytehound_scanner.dll") (Join-Path $InstallDir "bytehound_scanner.dll") -Force

$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
$Entries = @($UserPath -split ";" | Where-Object { $_ })
if ($Entries -notcontains $InstallDir) {
    [Environment]::SetEnvironmentVariable("Path", (($Entries + $InstallDir) -join ";"), "User")
}
$env:Path = "$InstallDir;$env:Path"

Write-Host "Installed bytehound to $InstallDir"
Write-Host "Open a new terminal, then run: bytehound --help"
