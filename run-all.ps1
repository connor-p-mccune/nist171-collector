<#
.SYNOPSIS
    Run the full nist171-collector pipeline: collect -> assess -> report, then open the report.

.DESCRIPTION
    Uses the read-only nist-scanner profile by default. Works from any PowerShell window:
    it runs the tool straight from the project's virtual environment, so the venv does not
    need to be activated first.

    PowerShell does not stop when a native program fails - even with
    $ErrorActionPreference = "Stop" - so every step checks $LASTEXITCODE itself. Without
    that, a failed collect would still run assess against an older evidence folder and
    produce a report that looks current but is not.

.PARAMETER AwsProfile
    AWS named profile to collect with. Defaults to nist-scanner.

.PARAMETER Poc
    Point of contact to record on each POA&M item. Defaults to TBD.

.PARAMETER NoOpen
    Write the report but do not open it.

.EXAMPLE
    .\run-all.ps1

.EXAMPLE
    .\run-all.ps1 -Poc "Jane Smith"
#>
[CmdletBinding()]
param(
    [string]$AwsProfile = "nist-scanner",
    [string]$Poc = "TBD",
    [switch]$NoOpen
)

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

$tool = Join-Path $PSScriptRoot ".venv\Scripts\nist171.exe"
if (-not (Test-Path $tool)) {
    Write-Host "Could not find $tool" -ForegroundColor Red
    Write-Host "Create the virtual environment and install the package first:"
    Write-Host "    python -m venv .venv"
    Write-Host "    .\.venv\Scripts\Activate.ps1"
    Write-Host "    pip install -r requirements.txt -r requirements-dev.txt"
    Write-Host "    pip install -e ."
    exit 1
}

function Invoke-Step {
    param([string]$Name, [string[]]$Arguments)
    Write-Host ""
    Write-Host "==> $Name" -ForegroundColor Cyan
    & $tool @Arguments
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Step '$Name' failed with exit code $LASTEXITCODE. Stopping." -ForegroundColor Red
        exit $LASTEXITCODE
    }
}

Invoke-Step "Collect evidence (profile: $AwsProfile)" @("collect", "--profile", $AwsProfile)
Invoke-Step "Assess and score" @("assess")
Invoke-Step "Write report and POA&M" @("report", "--format", "all", "--poc", $Poc)

$report = Join-Path $PSScriptRoot "output\report.html"
Write-Host ""
Write-Host "Done. Report: $report" -ForegroundColor Green

if (-not $NoOpen -and (Test-Path $report)) {
    Invoke-Item $report
}
