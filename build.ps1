param(
    [switch]$Test,
    [switch]$Clean,
    [string]$Configuration = "Release"
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot

if ($Clean) {
    Write-Host "[GateSentry] Cleaning build artifacts..." -ForegroundColor Yellow
    Get-ChildItem -Path $root -Include bin,obj -Recurse -Directory | Remove-Item -Recurse -Force
    Write-Host "[GateSentry] Cleanup complete." -ForegroundColor Green
    return
}

Write-Host "[GateSentry] Restoring and building GateSentry ($Configuration)..." -ForegroundColor Cyan
dotnet build "$root\GateSentry.slnx" -c $Configuration

if ($LASTEXITCODE -ne 0) {
    throw "Build failed with exit code $LASTEXITCODE"
}

if ($Test) {
    Write-Host "[GateSentry] Running test suite..." -ForegroundColor Cyan
    dotnet test "$root\GateSentry.slnx" -c $Configuration --no-build
    if ($LASTEXITCODE -ne 0) {
        throw "Tests failed with exit code $LASTEXITCODE"
    }
}

Write-Host "[GateSentry] Build completed successfully!" -ForegroundColor Green
