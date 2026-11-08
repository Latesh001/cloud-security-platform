# One-time setup: download portable PostgreSQL binaries, init the cluster,
# and create cloud_security_db. Safe to re-run; it skips steps that already exist.
# Usage:  .\scripts\setup-postgres.ps1

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$Root = Split-Path -Parent $PSScriptRoot
$Runtime = Join-Path $Root "runtime"
$PgRoot = Join-Path $Runtime "pgsql"
$PgData = Join-Path $Runtime "pgdata"
$PgBin = Join-Path $PgRoot "bin"
$PwFile = Join-Path $Runtime "pgpass.txt"

New-Item -ItemType Directory -Path $Runtime -Force | Out-Null

function Ensure-Binaries {
    $postgres = Join-Path $PgBin "postgres.exe"
    if (Test-Path $postgres) {
        Write-Host "PostgreSQL binaries already present."
        return
    }

    Write-Host "Downloading portable PostgreSQL Windows binaries (Maven Central)..."
    $metaUrl = "https://repo1.maven.org/maven2/io/zonky/test/postgres/embedded-postgres-binaries-windows-amd64/maven-metadata.xml"
    [xml]$meta = (Invoke-WebRequest -Uri $metaUrl -UseBasicParsing).Content
    $ver = $meta.metadata.versioning.release
    $jarUrl = "https://repo1.maven.org/maven2/io/zonky/test/postgres/embedded-postgres-binaries-windows-amd64/$ver/embedded-postgres-binaries-windows-amd64-$ver.jar"
    $jar = Join-Path $env:TEMP "pg-win-$ver.jar"
    Invoke-WebRequest -Uri $jarUrl -OutFile $jar -UseBasicParsing

    $extract = Join-Path $env:TEMP "pg-setup-extract"
    if (Test-Path $extract) { Remove-Item $extract -Recurse -Force }
    New-Item -ItemType Directory -Path $extract | Out-Null
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($jar, $extract)

    $txz = Join-Path $extract "postgres-windows-x86_64.txz"
    python -c @"
import lzma, tarfile, os, shutil
txz = r'$txz'
pg_root = r'$PgRoot'
tar_path = txz.replace('.txz', '.tar')
with lzma.open(txz, 'rb') as src, open(tar_path, 'wb') as dst:
    shutil.copyfileobj(src, dst)
dest = r'$env:TEMP\pg-setup-unpacked'
if os.path.exists(dest):
    shutil.rmtree(dest)
os.makedirs(dest)
with tarfile.open(tar_path, 'r') as tf:
    tf.extractall(dest)
postgres = None
for root, dirs, files in os.walk(dest):
    if 'postgres.exe' in files and os.path.basename(root) == 'bin':
        postgres = os.path.join(root, 'postgres.exe')
        break
if not postgres:
    raise SystemExit('postgres.exe not found in archive')
install_root = os.path.dirname(os.path.dirname(postgres))
if os.path.exists(pg_root):
    shutil.rmtree(pg_root)
os.makedirs(pg_root)
for name in os.listdir(install_root):
    shutil.move(os.path.join(install_root, name), os.path.join(pg_root, name))
print('Binaries installed to', pg_root)
"@
}

function Ensure-Cluster {
    if (Test-Path (Join-Path $PgData "PG_VERSION")) {
        Write-Host "Data directory already initialized."
        return
    }

    Set-Content -Path $PwFile -Value "postgres" -NoNewline -Encoding ascii
    Write-Host "Initializing database cluster..."
    & (Join-Path $PgBin "initdb.exe") -D $PgData -U postgres -A password --pwfile=$PwFile --encoding=UTF8 --locale=C | Out-Host

    Add-Content (Join-Path $PgData "postgresql.conf") "`nlisten_addresses = '127.0.0.1'`nport = 5432`n"
    @"
# TYPE  DATABASE        USER            ADDRESS                 METHOD
local   all             all                                     scram-sha-256
host    all             all             127.0.0.1/32            scram-sha-256
host    all             all             ::1/128                 scram-sha-256
"@ | Set-Content (Join-Path $PgData "pg_hba.conf") -Encoding ascii
}

function Ensure-Running {
    $pgCtl = Join-Path $PgBin "pg_ctl.exe"
    $status = & $pgCtl -D $PgData status 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "PostgreSQL already running."
        return
    }
    Write-Host "Starting PostgreSQL..."
    & $pgCtl -D $PgData -l (Join-Path $Runtime "postgres.log") start
    Start-Sleep -Seconds 2
}

function Ensure-Database {
    Write-Host "Ensuring cloud_security_db exists..."
    python -c @"
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
conn = psycopg2.connect(host='127.0.0.1', port=5432, user='postgres', password='postgres', dbname='postgres')
conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
cur = conn.cursor()
cur.execute(\"SELECT 1 FROM pg_database WHERE datname='cloud_security_db'\")
if cur.fetchone() is None:
    cur.execute('CREATE DATABASE cloud_security_db')
    print('Created cloud_security_db')
else:
    print('cloud_security_db already exists')
cur.close(); conn.close()
"@
}

Ensure-Binaries
Ensure-Cluster
Ensure-Running
Ensure-Database
Write-Host ""
Write-Host "PostgreSQL setup complete."
Write-Host "  Host:     127.0.0.1:5432"
Write-Host "  User:     postgres"
Write-Host "  Password: postgres"
Write-Host "  Database: cloud_security_db"
Write-Host "Start/stop later with scripts\start-postgres.ps1 and scripts\stop-postgres.ps1"
