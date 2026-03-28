param(
    [string]$Target = ""
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$rustDir = Resolve-Path (Join-Path $scriptDir "..")

Push-Location $rustDir
try {
    if ([string]::IsNullOrWhiteSpace($Target)) {
        cargo build --release --package opaque-ffi
    } else {
        cargo build --release --package opaque-ffi --target $Target
    }
}
finally {
    Pop-Location
}
