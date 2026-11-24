param(
    [Parameter(Mandatory = $true)]
    [string]$BackupFile,
    [Parameter(Mandatory = $true)]
    [string]$ConfirmDatabase
)

$ErrorActionPreference = "Stop"
$required = @("PGHOST", "PGPORT", "PGUSER", "PGPASSWORD", "PGDATABASE")
foreach ($name in $required) {
    if (-not [Environment]::GetEnvironmentVariable($name)) {
        throw "Set $name before running this restore."
    }
}
if ($ConfirmDatabase -cne $env:PGDATABASE) {
    throw "ConfirmDatabase must exactly match PGDATABASE. Restore only to a new, empty recovery database."
}
if (-not (Test-Path -LiteralPath $BackupFile -PathType Leaf)) {
    throw "Backup file does not exist: $BackupFile"
}

$psql = Get-Command psql -ErrorAction Stop
$pgRestore = Get-Command pg_restore -ErrorAction Stop
$env:PGSSLMODE = "require"
$objectCount = & $psql.Source --no-psqlrc --tuples-only --no-align --command "SELECT (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')) + (SELECT count(*) FROM pg_namespace WHERE nspname NOT IN ('pg_catalog', 'information_schema', 'public'));"
if ($LASTEXITCODE -ne 0) {
    throw "Could not verify that the target database is empty"
}
if ([int]$objectCount.Trim() -ne 0) {
    throw "Restore refused: target database is not empty. Create a separate empty recovery database."
}

& $pgRestore.Source --exit-on-error --no-owner --dbname=$env:PGDATABASE $BackupFile
if ($LASTEXITCODE -ne 0) {
    throw "pg_restore failed with exit code $LASTEXITCODE"
}
Write-Output "Restore completed to the verified empty database: $env:PGDATABASE"
