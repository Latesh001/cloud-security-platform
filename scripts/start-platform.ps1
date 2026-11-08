# Start the full local stack: MongoDB + Flask + Vite
# Usage:  .\scripts\start-platform.ps1

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

Write-Host "=== 1/3  MongoDB Database ===" -ForegroundColor Cyan
$mongo = Get-Service -Name "MongoDB" -ErrorAction SilentlyContinue
if ($mongo) {
    if ($mongo.Status -ne "Running") {
        try {
            Start-Service MongoDB
            Write-Host "MongoDB service started successfully."
        } catch {
            Write-Warning "Could not start MongoDB service (may need Administrator privileges)."
        }
    } else {
        Write-Host "MongoDB service is running."
    }
} else {
    Write-Host "MongoDB Windows service not found. Confirm local MongoDB server is listening on port 27017."
}

Write-Host ""
Write-Host "=== 2/3  Backend (Flask :5000) ===" -ForegroundColor Cyan
$envFile = Join-Path $Root "backend\.env"
if (-not (Test-Path $envFile)) {
    Copy-Item (Join-Path $Root "backend\.env.example") $envFile
    Write-Host "Created backend\.env from .env.example."
}

$backendCmd = "Set-Location `"$Root\backend`"; python app.py"
Start-Process powershell -ArgumentList "-NoExit", "-Command", $backendCmd -WindowStyle Normal
Write-Host "Backend starting in a new window..."

Write-Host ""
Write-Host "=== 3/3  Frontend (Vite :5173) ===" -ForegroundColor Cyan
if (-not (Test-Path (Join-Path $Root "frontend\node_modules"))) {
    Write-Host "Installing frontend dependencies (first run)..."
    if ($env:NODE_EXTRA_CA_CERTS) {
        Write-Host "Using NODE_EXTRA_CA_CERTS=$env:NODE_EXTRA_CA_CERTS"
    }
    Push-Location (Join-Path $Root "frontend")
    npm install --no-audit --no-fund
    Pop-Location
}

$frontendCmd = "Set-Location `"$Root\frontend`"; if (`$env:NODE_EXTRA_CA_CERTS) { Write-Host `"CA: `$env:NODE_EXTRA_CA_CERTS`" }; npm run dev"
Start-Process powershell -ArgumentList "-NoExit", "-Command", $frontendCmd -WindowStyle Normal
Write-Host "Frontend starting in a new window..."

Write-Host ""
Write-Host "Waiting for health check..." -ForegroundColor Cyan
$healthy = $false
for ($i = 0; $i -lt 30; $i++) {
    Start-Sleep -Seconds 1
    try {
        $r = Invoke-RestMethod -Uri "http://127.0.0.1:5000/api/health" -TimeoutSec 2
        Write-Host ("Health: status={0} mongodb={1}" -f $r.status, $r.mongodb)
        $healthy = $true
        break
    } catch {
        Write-Host -NoNewline "."
    }
}
Write-Host ""
if (-not $healthy) {
    Write-Warning "Backend health check did not succeed yet. Check the backend window for errors."
}

Write-Host ""
Write-Host "Open the app:  http://localhost:5173" -ForegroundColor Green
Write-Host "API health:    http://localhost:5000/api/health"
Write-Host "OTPs/links print in the backend console when email is not configured."
