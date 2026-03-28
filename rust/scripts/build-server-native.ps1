param(
    [string]$Target = ""
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$rustDir = Resolve-Path (Join-Path $scriptDir "..")

$previousRustFlags = $env:RUSTFLAGS
if ([string]::IsNullOrWhiteSpace($previousRustFlags)) {
    $env:RUSTFLAGS = "-C target-cpu=native"
} else {
    $env:RUSTFLAGS = "$previousRustFlags -C target-cpu=native"
}

Push-Location $rustDir
try {
    if ([string]::IsNullOrWhiteSpace($Target)) {
        cargo build --release --package opaque-ffi
    } else {
        cargo build --release --package opaque-ffi --target $Target
    }
}
finally {
    if ($null -eq $previousRustFlags) {
        Remove-Item Env:RUSTFLAGS -ErrorAction SilentlyContinue
    } else {
        $env:RUSTFLAGS = $previousRustFlags
    }
    Pop-Location
}
