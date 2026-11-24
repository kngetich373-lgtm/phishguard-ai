param(
    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory
)

$ErrorActionPreference = "Stop"
$required = @("PGHOST", "PGPORT", "PGUSER", "PGPASSWORD", "PGDATABASE")
foreach ($name in $required) {
    if (-not [Environment]::GetEnvironmentVariable($name)) {
        throw "Set $name before running this backup."
    }
}

$pgDump = Get-Command pg_dump -ErrorAction Stop
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$stamp = [DateTime]::UtcNow.ToString("yyyyMMddTHHmmssZ")
$file = Join-Path $OutputDirectory "phishguard-$stamp.dump"
$env:PGSSLMODE = "require"

& $pgDump.Source --format=custom --no-owner --file=$file
if ($LASTEXITCODE -ne 0) {
    throw "pg_dump failed with exit code $LASTEXITCODE"
}
if (-not (Test-Path -LiteralPath $file) -or (Get-Item -LiteralPath $file).Length -eq 0) {
    throw "pg_dump did not produce a non-empty backup file"
}
Write-Output "Backup created: $file"
