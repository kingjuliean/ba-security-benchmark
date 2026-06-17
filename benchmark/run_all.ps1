# run_all.ps1 — läuft alle 9 Tools, 3× gegen beide Targets

$tools = @("semgrep", "npm-audit", "dependency-check", "zap-baseline", "nuclei", "snyk")
$targets = @("juiceshop", "vulnerableshop")
$runs = 3

# CSV-Header anlegen
$timingFile = "results\timing.csv"
Set-Content -Path $timingFile -Value "tool,target,run,duration_seconds,timestamp"

# Juice Shop starten
Write-Host "Starte Juice Shop..." -ForegroundColor Cyan
Set-Location ..\targets\juice-shop
docker-compose up -d
Start-Sleep -Seconds 15  # Warten bis App bereit

# Vulnerable Shop starten
Write-Host "Starte Vulnerable Shop..." -ForegroundColor Cyan
Set-Location ..\vulnerable-shop
docker-compose up -d
Start-Sleep -Seconds 10

Set-Location ..\..\benchmark

# Alle Kombinationen durchlaufen
foreach ($target in $targets) {
    foreach ($tool in $tools) {
        foreach ($run in 1..$runs) {
            Write-Host "`n--- $tool / $target / Run $run ---" -ForegroundColor Magenta
            .\run_benchmark.ps1 -Tool $tool -Target $target -Run $run
            Start-Sleep -Seconds 5  # Kurze Pause zwischen Runs
        }
    }
}

Write-Host "`n=== ALLE RUNS FERTIG ===" -ForegroundColor Green
Write-Host "Ergebnisse in: benchmark\results\" -ForegroundColor Yellow