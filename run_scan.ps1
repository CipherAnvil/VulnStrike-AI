param (
    [string]$Url = "http://localhost:8080/vulnerabilities/sqli/",
    [string]$Param = "id",
    [string]$Type = "all",
    [string]$Out = "vulnstrike_report.json"
)

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "   VulnStrike AI -- Server Exploit Engine " -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Cyan

# Check if Python is installed
$pythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCmd) {
    Write-Host "[!] Python is not installed or not in PATH." -ForegroundColor Red
    Write-Host "[*] Please install Python 3.10+ and ensure 'Add Python to PATH' is checked." -ForegroundColor Yellow
    exit 1
}

# Setup venv if it does not exist
if (-not (Test-Path "venv")) {
    Write-Host "[*] Creating virtual environment (venv)..." -ForegroundColor Yellow
    python -m venv venv
    Write-Host "[*] Installing dependencies from requirements.txt..." -ForegroundColor Yellow
    .\venv\Scripts\python.exe -m pip install -r requirements.txt
}

# Run exploit engine inside venv
Write-Host "[*] Launching scanner against: $Url" -ForegroundColor Cyan
.\venv\Scripts\python.exe exploit_engine.py --url $Url --param $Param --type $Type --out $Out
