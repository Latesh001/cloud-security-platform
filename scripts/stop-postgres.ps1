# Stop the portable PostgreSQL instance
# Usage:  .\scripts\stop-postgres.ps1

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$PgCtl = Join-Path $Root "runtime\pgsql\bin\pg_ctl.exe"
$PgData = Join-Path $Root "runtime\pgdata"

if (-not (Test-Path $PgCtl)) {
    Write-Host "Portable PostgreSQL is not installed."
    exit 0
}

$status = & $PgCtl -D $PgData status 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "PostgreSQL is not running."
    exit 0
}

Write-Host "Stopping PostgreSQL..."
& $PgCtl -D $PgData stop -m fast
Write-Host "PostgreSQL stopped."
