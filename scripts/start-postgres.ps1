# Start the portable PostgreSQL instance bundled under runtime/
# Usage:  .\scripts\start-postgres.ps1

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$PgBin = Join-Path $Root "runtime\pgsql\bin"
$PgData = Join-Path $Root "runtime\pgdata"
$LogFile = Join-Path $Root "runtime\postgres.log"
$PgCtl = Join-Path $PgBin "pg_ctl.exe"

if (-not (Test-Path $PgCtl)) {
    Write-Error "Portable PostgreSQL not found at $PgBin. Run scripts\setup-postgres.ps1 first."
}

if (-not (Test-Path $PgData)) {
    Write-Error "Data directory missing at $PgData. Run scripts\setup-postgres.ps1 first."
}

$status = & $PgCtl -D $PgData status 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "PostgreSQL is already running."
    exit 0
}

Write-Host "Starting PostgreSQL..."
& $PgCtl -D $PgData -l $LogFile start
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to start PostgreSQL. See $LogFile"
}

Start-Sleep -Seconds 2
& $PgCtl -D $PgData status
Write-Host "PostgreSQL ready on 127.0.0.1:5432 (database: cloud_security_db)"
