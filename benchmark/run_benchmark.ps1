#Requires -Version 5.1
<#
.SYNOPSIS
    Lokaler Benchmark-Runner für alle 9 Security-Tools (FF1 -- Detektionsqualität).

.DESCRIPTION
    Startet ein oder alle Tools gegen ein oder beide Targets.
    Speichert Output: benchmark/results/<tool>/<target>/run_<n>.<ext>
    Loggt Timing:     benchmark/results/timing.csv

.PARAMETER Tool
    semgrep | codeql | sonarqube | zap | nuclei | dastardly |
    dependency-check | snyk | npm-audit | all

.PARAMETER Target
    vulnerable-shop | juice-shop | all

.PARAMETER Run
    Run-Nummer (1-N). 0 = alle Runs ausführen (Default).

.PARAMETER Runs
    Anzahl Wiederholungen pro ToolxTarget-Kombination (Default: 3).

.PARAMETER SkipStartup
    Targets nicht (neu) starten -- nützlich wenn bereits laufen.

.EXAMPLE
    # Einzelner Run
    .\run_benchmark.ps1 -Tool semgrep -Target vulnerable-shop -Run 1

    # Alle Tools, alle Targets, 3 Runs
    .\run_benchmark.ps1 -Tool all -Target all

    # Nur DAST gegen juice-shop, Targets bereits gestartet
    .\run_benchmark.ps1 -Tool zap -Target juice-shop -SkipStartup
#>
param(
    [ValidateSet("semgrep","codeql","sonarqube","zap","nuclei","dastardly",
                 "dependency-check","snyk","npm-audit","all")]
    [string]$Tool = "all",

    [ValidateSet("vulnerable-shop","juice-shop","all")]
    [string]$Target = "all",

    [int]$Run  = 0,
    [int]$Runs = 3,
    [switch]$SkipStartup
)

Set-StrictMode -Version Latest
# Continue statt Stop: Ein fehlgeschlagenes Tool stoppt nicht den Gesamtlauf
$ErrorActionPreference = "Continue"

# -- Gepinnte Tool-Versionen (Reproduzierbarkeit) ------------------------------
# Versions hier ändern um einen neuen Benchmark-Snapshot zu erstellen.
# Doku-Pflicht: jede Änderung -> Eintrag in benchmark/tool-setup-times.md
$Images = @{
    # SAST
    "semgrep"          = "semgrep/semgrep:1.77.0"
    # CodeQL: mcr.microsoft.com-Image hat kein stabiles Versions-Tagging.
    # Empfehlung: Tag aus `docker inspect` nach Pull dokumentieren.
    "codeql"           = "mcr.microsoft.com/cstsectools/codeql-container:latest"
    "sonarqube"        = "sonarqube:9.9.8-community"          # LTS-Linie
    "sonar-scanner"    = "sonarsource/sonar-scanner-cli:11.0"
    # DAST
    "zap"              = "ghcr.io/zaproxy/zaproxy:2.15.0"
    "nuclei"           = "projectdiscovery/nuclei:v3.3.4"
    # Dastardly: PortSwigger stellt keine versionierten Tags bereit.
    # Workaround: Image-SHA nach Pull in tool-setup-times.md festhalten.
    "dastardly"        = "public.ecr.aws/portswigger/dastardly:latest"
    # SCA
    "dependency-check" = "owasp/dependency-check:12.1.0"
    "snyk"             = "snyk/snyk:node-18"
}

# -- Pfade ---------------------------------------------------------------------

$RepoRoot    = (Resolve-Path "$PSScriptRoot\..").Path
$ResultsDir  = Join-Path $PSScriptRoot "results"
$TimingFile  = Join-Path $ResultsDir   "timing.csv"
$TargetsDir  = Join-Path $RepoRoot     "targets"
$DcCacheDir  = Join-Path $PSScriptRoot ".dc-cache"  # NVD-Daten zwischen Runs teilen

# -- Target-Konfiguration ------------------------------------------------------

$Targets = @{
    "vulnerable-shop" = @{
        SourcePath = Join-Path $TargetsDir "vulnerable-shop\Shop"
        ComposeDir = Join-Path $TargetsDir "vulnerable-shop\Shop"
        HostUrl    = "http://localhost:3001"
        # host.docker.internal: auf Windows Docker Desktop immer verfügbar
        DockerUrl  = "http://host.docker.internal:3001"
        Port       = 3001
    }
    "juice-shop" = @{
        SourcePath = Join-Path $TargetsDir "juice-shop\src"
        ComposeDir = Join-Path $TargetsDir "juice-shop"
        HostUrl    = "http://localhost:3000"
        DockerUrl  = "http://host.docker.internal:3000"
        Port       = 3000
    }
}

$AllTools  = @("semgrep","codeql","sonarqube",
               "zap","nuclei","dastardly",
               "dependency-check","snyk","npm-audit")

$DastTools = @("zap","nuclei","dastardly")

# -- Logging-Hilfsfunktionen ---------------------------------------------------

function Log-Header([string]$msg) {
    Write-Host ("`n" + ("-" * 68)) -ForegroundColor Cyan
    Write-Host "  $msg" -ForegroundColor Cyan
    Write-Host ("-" * 68) -ForegroundColor Cyan
}
function Log-Step([string]$msg)  { Write-Host "  -> $msg" -ForegroundColor DarkGray }
function Log-Ok([string]$msg)    { Write-Host "  [OK] $msg" -ForegroundColor Green }
function Log-Warn([string]$msg)  { Write-Host "  [!!] $msg" -ForegroundColor Yellow }
function Log-Err([string]$msg)   { Write-Host "  [XX] $msg" -ForegroundColor Red }

# Löst Pfad auf (Abs = Absolutpfad, Fehler toleriert)
function Abs([string]$p) {
    try { (Resolve-Path $p -ErrorAction Stop).Path }
    catch { $p }
}

# Erstellt Output-Verzeichnis und gibt Zielpfad zurück
function OutPath([string]$tool, [string]$tgt, [int]$run, [string]$ext) {
    $dir = Join-Path $ResultsDir "$tool\$tgt"
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    return Join-Path $dir "run_${run}.${ext}"
}

# Schreibt eine Zeile in timing.csv
function Append-Timing([string]$tool, [string]$tgt, [int]$run, [double]$sec, [string]$st) {
    if (-not (Test-Path $TimingFile)) {
        "tool,target,run,duration_seconds,status,timestamp" |
            Set-Content $TimingFile -Encoding UTF8
    }
    "$tool,$tgt,$run,$([math]::Round($sec,2)),$st,$(Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')" |
        Add-Content $TimingFile -Encoding UTF8
}

# Wartet bis HTTP-Endpunkt antwortet (max. $timeoutSec Sekunden)
function Wait-Http([string]$url, [int]$timeoutSec = 90) {
    Log-Step "Warte auf $url (max. ${timeoutSec}s)..."
    $limit = (Get-Date).AddSeconds($timeoutSec)
    while ((Get-Date) -lt $limit) {
        try {
            $r = Invoke-WebRequest $url -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop
            if ($r.StatusCode -lt 500) { Log-Ok "Erreichbar."; return $true }
        } catch {}
        Start-Sleep 3
    }
    Log-Warn "Timeout -- $url nicht erreichbar."
    return $false
}

# -- Target-Verwaltung ---------------------------------------------------------

function Start-AppTarget([string]$name) {
    $cfg = $Targets[$name]
    Log-Step "Starte $name (docker compose up -d)..."
    Push-Location $cfg.ComposeDir
    docker compose up -d 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { Log-Warn "docker compose up fehlgeschlagen fuer $name -- Target laeuft moeglicherweise nicht." }
    Pop-Location
    $reachable = Wait-Http $cfg.HostUrl -timeoutSec 120
    if (-not $reachable) { Log-Warn "$name nicht erreichbar nach 120s -- DAST-Scan kann fehlschlagen." }
}

# -- SAST: Semgrep -------------------------------------------------------------

function Run-Semgrep([string]$tgt, [int]$run) {
    $cfg    = $Targets[$tgt]
    $src    = Abs $cfg.SourcePath
    $out    = OutPath "semgrep" $tgt $run "sarif"
    $outDir = Abs (Split-Path $out)
    $outFile = Split-Path $out -Leaf

    # juice-shop: Quellcode nicht im Repo -- einmalig klonen
    if ($tgt -eq "juice-shop" -and -not (Test-Path (Join-Path $src "package.json"))) {
        Log-Step "Klone juice-shop Quellcode (einmalig)..."
        git -c http.sslVerify=false clone --depth 1 https://github.com/juice-shop/juice-shop.git $src 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { Log-Err "git clone fehlgeschlagen."; return $false }
    }

    Log-Step "Image: $($Images['semgrep'])"

    docker run --rm `
        --name "bench-semgrep-${tgt}-r${run}" `
        -v "${src}:/src:ro" `
        -v "${outDir}:/out" `
        $Images["semgrep"] `
        semgrep scan `
            --config "p/owasp-top-ten" `
            --config "p/javascript" `
            --config "p/nodejs" `
            --sarif `
            --output "/out/${outFile}" `
            /src
    # Exit-Code 1 bei Findings ist normal
    if (Test-Path $out) { Log-Ok "-> $out"; return $true }
    Log-Warn "Semgrep: keine SARIF-Ausgabe."; return $false
}

# -- SAST: CodeQL --------------------------------------------------------------

function Run-CodeQL([string]$tgt, [int]$run) {
    $cfg    = $Targets[$tgt]
    $src    = Abs $cfg.SourcePath
    $out    = OutPath "codeql" $tgt $run "sarif"
    $outDir = Abs (Split-Path $out)

    if ($tgt -eq "juice-shop" -and -not (Test-Path (Join-Path $src "package.json"))) {
        Log-Warn "juice-shop Quellcode fehlt -- CodeQL übersprungen."; return $false
    }

    # Datenbank-Verzeichnis (pro Run getrennt)
    $dbDir = Join-Path $outDir "codeql_db_run${run}"
    New-Item -ItemType Directory -Force -Path $dbDir | Out-Null
    $dbAbs = Abs $dbDir

    Log-Step "Image: $($Images['codeql'])"
    Log-Step "Phase 1/2: Datenbank erstellen..."

    docker run --rm `
        --name "bench-codeql-db-${tgt}-r${run}" `
        -v "${src}:/src:ro" `
        -v "${dbAbs}:/db" `
        $Images["codeql"] `
        codeql database create /db `
            --language=javascript-typescript `
            --source-root=/src `
            --overwrite
    if ($LASTEXITCODE -ne 0) { Log-Err "CodeQL DB-Erstellung fehlgeschlagen."; return $false }

    Log-Step "Phase 2/2: Queries ausführen..."

    docker run --rm `
        --name "bench-codeql-analyze-${tgt}-r${run}" `
        -v "${dbAbs}:/db:ro" `
        -v "${outDir}:/out" `
        $Images["codeql"] `
        codeql database analyze /db `
            "javascript-security-and-quality.qls" `
            --format=sarif-latest `
            --output="/out/run_${run}.sarif" `
            --threads=0

    if (Test-Path $out) { Log-Ok "-> $out"; return $true }
    Log-Warn "CodeQL: keine SARIF-Ausgabe."; return $false
}

# -- SAST: SonarQube Community Edition ----------------------------------------

function Run-SonarQube([string]$tgt, [int]$run) {
    $cfg     = $Targets[$tgt]
    $src     = Abs $cfg.SourcePath
    $out     = OutPath "sonarqube" $tgt $run "json"
    $sqNet   = "bench-sonarqube-net"
    $sqCont  = "bench-sonarqube-server"
    $sqPort  = 9000
    $sqPass  = "BenchmarkAdmin2024!"
    $projKey = "bench-$($tgt -replace '-','')"

    Log-Step "Image: $($Images['sonarqube']) + $($Images['sonar-scanner'])"

    # SonarQube-Server starten falls nicht bereits läuft
    $exists = docker ps -a --filter "name=$sqCont" --format "{{.Names}}" 2>&1
    if ($exists -notmatch $sqCont) {
        Log-Step "Erstelle SonarQube-Server (einmaliges Erststart)..."
        # Netzwerk nur erstellen wenn es noch nicht existiert
        $netExists = docker network ls --filter "name=$sqNet" --format "{{.Name}}" 2>&1
        if ($netExists -notmatch $sqNet) {
            docker network create $sqNet 2>&1 | Out-Null
            if ($LASTEXITCODE -ne 0) { Log-Err "Netzwerk '$sqNet' konnte nicht erstellt werden."; return $false }
            Log-Step "Netzwerk '$sqNet' erstellt."
        }
        docker run -d `
            --name $sqCont `
            --network $sqNet `
            -p "${sqPort}:9000" `
            -e SONAR_ES_BOOTSTRAP_CHECKS_DISABLE=true `
            $Images["sonarqube"] 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { Log-Err "SonarQube-Container konnte nicht gestartet werden."; return $false }
    } else {
        docker start $sqCont 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { Log-Err "SonarQube-Container konnte nicht neu gestartet werden."; return $false }
    }

    # Warten bis SonarQube UP-Status meldet
    Log-Step "Warte auf SonarQube (bis 150s)..."
    $limit = (Get-Date).AddSeconds(150)
    $up = $false
    while ((Get-Date) -lt $limit) {
        try {
            $st = (Invoke-RestMethod "http://localhost:${sqPort}/api/system/status" -EA Stop).status
            if ($st -eq "UP") { $up = $true; break }
        } catch {}
        Start-Sleep 5
    }
    if (-not $up) { Log-Err "SonarQube nicht erreichbar."; return $false }
    Log-Ok "SonarQube UP."

    # Admin-Passwort beim ersten Start auf sicheren Wert ändern (idempotent)
    $b64def = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("admin:admin"))
    try {
        Invoke-RestMethod "http://localhost:${sqPort}/api/users/change_password" `
            -Method POST `
            -Headers @{ Authorization = "Basic $b64def" } `
            -Body "login=admin&previousPassword=admin&password=$sqPass" `
            -EA SilentlyContinue | Out-Null
    } catch {}

    # Scanner-Container im selben Netzwerk ausführen
    docker run --rm `
        --name "bench-sonar-scan-${tgt}-r${run}" `
        --network $sqNet `
        -v "${src}:/usr/src:ro" `
        $Images["sonar-scanner"] `
        sonar-scanner `
            -Dsonar.projectKey=$projKey `
            -Dsonar.projectName="benchmark-$tgt" `
            -Dsonar.sources=/usr/src `
            "-Dsonar.host.url=http://${sqCont}:9000" `
            -Dsonar.login=admin `
            "-Dsonar.password=$sqPass" `
            -Dsonar.scm.disabled=true `
            -Dsonar.javascript.node.maxspace=2048

    # Auf Background-Analyse-Task warten
    Start-Sleep 20

    # Issues per REST-API abrufen und als JSON speichern
    $b64new = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("admin:$sqPass"))
    try {
        $issueUrl = "http://localhost:${sqPort}/api/issues/search" +
                    "?componentKeys=${projKey}&ps=500&resolved=false"
        $resp = Invoke-WebRequest $issueUrl `
            -Headers @{ Authorization = "Basic $b64new" } `
            -UseBasicParsing -EA Stop
        $resp.Content | Set-Content $out -Encoding UTF8
        Log-Ok "-> $out (JSON; Konvertierung zu SARIF via analysis/convert_to_sarif.py)"
        return $true
    } catch {
        Log-Err "SonarQube API-Abruf fehlgeschlagen: $_"
        return $false
    }
}

# -- DAST: OWASP ZAP -----------------------------------------------------------

function Run-ZAP([string]$tgt, [int]$run) {
    $cfg    = $Targets[$tgt]
    $outDir = Abs (Join-Path $ResultsDir "zap\$tgt")
    New-Item -ItemType Directory -Force $outDir | Out-Null
    $out    = OutPath "zap" $tgt $run "json"

    Log-Step "Image: $($Images['zap'])"

    # vulnerable-shop hat Automation-Framework-Konfiguration
    $zapYml = Join-Path $cfg.SourcePath ".zap\automation.yml"
    if (Test-Path $zapYml) {
        # Temp-Kopie mit Docker-kompatibler URL erstellen
        $tmpYml = Join-Path $env:TEMP "bench_zap_${tgt}_r${run}.yml"
        (Get-Content $zapYml -Raw) `
            -replace [regex]::Escape("http://localhost:3000"), $cfg.DockerUrl `
            -replace [regex]::Escape("http://localhost:3001"), $cfg.DockerUrl |
            Set-Content $tmpYml -Encoding UTF8

        $tmpYmlDir = Abs (Split-Path $tmpYml)
        $tmpYmlFile = Split-Path $tmpYml -Leaf

        Log-Step "Automation-Framework-Scan (aus $zapYml)"
        docker run --rm `
            --name "bench-zap-${tgt}-r${run}" `
            -v "${tmpYmlDir}:/zap/config:ro" `
            -v "${outDir}:/zap/reports" `
            --add-host "host.docker.internal:host-gateway" `
            $Images["zap"] `
            zap.sh -cmd `
                -autorun "/zap/config/${tmpYmlFile}"

        Remove-Item $tmpYml -Force -ErrorAction SilentlyContinue

        # Automation-Framework schreibt Report per automation.yml-Definition
        $rptJson = Get-ChildItem $outDir -Filter "*.json" |
                   Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($rptJson) {
            Copy-Item $rptJson.FullName $out -Force | Out-Null
            Log-Ok "-> $out (JSON; Konvertierung zu SARIF via analysis/convert_to_sarif.py)"
            return $true
        }
    }

    # Fallback: zap-full-scan.py
    Log-Step "Fallback: zap-full-scan.py gegen $($cfg.DockerUrl)"
    docker run --rm `
        --name "bench-zap-fallback-${tgt}-r${run}" `
        -v "${outDir}:/zap/wrk" `
        --add-host "host.docker.internal:host-gateway" `
        $Images["zap"] `
        zap-full-scan.py `
            -t $cfg.DockerUrl `
            -J "run_${run}.json" `
            -r "run_${run}.html" `
            -x "run_${run}.xml" `
            -l WARN

    if (Test-Path $out) { Log-Ok "-> $out"; return $true }
    Log-Warn "ZAP: kein Output erzeugt."; return $false
}

# -- DAST: Nuclei --------------------------------------------------------------

function Run-Nuclei([string]$tgt, [int]$run) {
    $cfg    = $Targets[$tgt]
    $outDir = Abs (Join-Path $ResultsDir "nuclei\$tgt")
    New-Item -ItemType Directory -Force $outDir | Out-Null
    $out    = OutPath "nuclei" $tgt $run "json"

    Log-Step "Image: $($Images['nuclei'])"

    docker run --rm `
        --name "bench-nuclei-${tgt}-r${run}" `
        -v "${outDir}:/output" `
        --add-host "host.docker.internal:host-gateway" `
        $Images["nuclei"] `
        -u $cfg.DockerUrl `
        -severity "critical,high,medium,low" `
        -json-export "/output/run_${run}.json" `
        -silent

    # Keine Findings != Fehler -- leere Datei erstellen
    if (-not (Test-Path $out)) {
        "[]" | Set-Content $out -Encoding UTF8
    }
    Log-Ok "-> $out (JSON; Konvertierung zu SARIF via analysis/convert_to_sarif.py)"
    return $true
}

# -- DAST: Burp Dastardly ------------------------------------------------------

function Run-Dastardly([string]$tgt, [int]$run) {
    $cfg    = $Targets[$tgt]
    $outDir = Abs (Join-Path $ResultsDir "dastardly\$tgt")
    New-Item -ItemType Directory -Force $outDir | Out-Null
    $out    = OutPath "dastardly" $tgt $run "xml"

    Log-Step "Image: $($Images['dastardly'])  [!!] kein Versions-Tagging verfügbar"
    Log-Step "Ziel: $($cfg.DockerUrl)"

    docker run --rm `
        --name "bench-dastardly-${tgt}-r${run}" `
        -v "${outDir}:/dastardly-reports" `
        --add-host "host.docker.internal:host-gateway" `
        -e BURP_START_URL=$cfg.DockerUrl `
        -e BURP_REPORT_FILE_PATH="/dastardly-reports/run_${run}.xml" `
        $Images["dastardly"]
    # Exit-Code 1 bei Findings ist normal

    if (Test-Path $out) { Log-Ok "-> $out (JUnit-XML)"; return $true }
    Log-Warn "Dastardly: kein Report. Prüfe ob App auf $($cfg.DockerUrl) erreichbar ist."
    return $false
}

# -- SCA: OWASP Dependency-Check -----------------------------------------------

function Run-DependencyCheck([string]$tgt, [int]$run) {
    $cfg    = $Targets[$tgt]
    $src    = Abs $cfg.SourcePath
    $outDir = Abs (Join-Path $ResultsDir "dependency-check\$tgt")
    New-Item -ItemType Directory -Force $outDir  | Out-Null
    New-Item -ItemType Directory -Force $DcCacheDir | Out-Null
    $out    = OutPath "dependency-check" $tgt $run "json"
    $cache  = Abs $DcCacheDir

    Log-Step "Image: $($Images['dependency-check'])"
    Log-Step "NVD-Cache: $DcCacheDir (zwischen Runs geteilt)"

    $nvdArgs = @()
    if ($env:NVD_API_KEY) {
        Log-Step "NVD API-Key gesetzt -- Rate-Limit aufgehoben."
        $nvdArgs = @("--nvdApiKey", $env:NVD_API_KEY)
    } else {
        Log-Warn "NVD_API_KEY nicht gesetzt -- Download sehr langsam. Empfehlung: `$env:NVD_API_KEY='...' setzen."
    }

    docker run --rm `
        --name "bench-depcheck-${tgt}-r${run}" `
        -e "JAVA_OPTS=-Xmx4g" `
        -v "${src}:/src:ro" `
        -v "${outDir}:/report" `
        -v "${cache}:/usr/share/dependency-check/data" `
        $Images["dependency-check"] `
        --scan /src `
        --exclude "**/node_modules/**" `
        --format JSON `
        --format SARIF `
        --out /report `
        --project "benchmark-${tgt}" `
        --enableExperimental `
        --failOnCVSS 0 `
        @nvdArgs

    $srcJson  = Join-Path $outDir "dependency-check-report.json"
    $srcSarif = Join-Path $outDir "dependency-check-report.sarif"

    if (Test-Path $srcSarif) {
        Copy-Item $srcSarif (OutPath "dependency-check" $tgt $run "sarif") -Force | Out-Null
    }
    if (Test-Path $srcJson) {
        Copy-Item $srcJson $out -Force | Out-Null
        Log-Ok "-> $out (+ .sarif wenn erzeugt)"; return $true
    }
    Log-Warn "Dependency-Check: kein Report."; return $false
}

# -- SCA: Snyk -----------------------------------------------------------------

function Run-Snyk([string]$tgt, [int]$run) {
    $cfg = $Targets[$tgt]
    $src = Abs $cfg.SourcePath
    $out = OutPath "snyk" $tgt $run "json"

    if (-not $env:SNYK_TOKEN) {
        Log-Warn "SNYK_TOKEN nicht gesetzt -- Snyk übersprungen."
        Log-Warn "Token kostenlos: https://app.snyk.io/account | dann: `$env:SNYK_TOKEN='dein-token'"
        return $false
    }

    Log-Step "Image: $($Images['snyk'])"

    # Snyk gibt Exit-Code 1 bei Findings -- Ausgabe in Datei umleiten
    $tmpOut = Join-Path $env:TEMP "snyk_${tgt}_r${run}.json"
    docker run --rm `
        --name "bench-snyk-${tgt}-r${run}" `
        -v "${src}:/project:ro" `
        -e "SNYK_TOKEN=$env:SNYK_TOKEN" `
        -w /project `
        $Images["snyk"] `
        snyk test --json --all-projects 2>&1 | Set-Content $tmpOut -Encoding UTF8

    if (Test-Path $tmpOut) {
        Move-Item $tmpOut $out -Force
        Log-Ok "-> $out (JSON; Konvertierung zu SARIF via analysis/convert_to_sarif.py)"
        return $true
    }
    return $false
}

# -- SCA: npm audit ------------------------------------------------------------

function Run-NpmAudit([string]$tgt, [int]$run) {
    $cfg = $Targets[$tgt]
    $src = $cfg.SourcePath
    $out = OutPath "npm-audit" $tgt $run "json"

    if (-not (Test-Path (Join-Path $src "package.json"))) {
        Log-Warn "package.json nicht gefunden in $src"; return $false
    }

    Log-Step "npm audit --json (nativ, kein Docker)"
    Push-Location $src
    # npm audit gibt Exit-Code 1 bei Findings -- das ist normales Verhalten
    $result = & npm audit --json 2>&1
    $result | Set-Content $out -Encoding UTF8
    Pop-Location

    Log-Ok "-> $out (JSON; Konvertierung zu SARIF via analysis/convert_to_sarif.py)"
    return (Test-Path $out)
}

# -- Tool-Dispatcher -----------------------------------------------------------

function Invoke-Tool([string]$tool, [string]$tgt, [int]$run) {
    Log-Header "$tool | $tgt | Run $run"

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $ok = $false

    try {
        $ok = & {
            switch ($tool) {
                "semgrep"          { Run-Semgrep          $tgt $run }
                "codeql"           { Run-CodeQL           $tgt $run }
                "sonarqube"        { Run-SonarQube        $tgt $run }
                "zap"              { Run-ZAP              $tgt $run }
                "nuclei"           { Run-Nuclei           $tgt $run }
                "dastardly"        { Run-Dastardly        $tgt $run }
                "dependency-check" { Run-DependencyCheck  $tgt $run }
                "snyk"             { Run-Snyk             $tgt $run }
                "npm-audit"        { Run-NpmAudit         $tgt $run }
            }
        }
    } catch {
        Log-Err "Unbehandelte Ausnahme bei ${tool}: $_"
        $ok = $false
    }

    $sw.Stop()
    $secs   = $sw.Elapsed.TotalSeconds
    $status = if ($ok) { "OK" } else { "FAIL" }
    Append-Timing $tool $tgt $run $secs $status

    $col = if ($ok) { "Green" } else { "Yellow" }
    Write-Host "  Dauer: $([math]::Round($secs,1))s  |  Status: $status" -ForegroundColor $col

    return $ok
}

# -- Haupt-Orchestrierung ------------------------------------------------------

New-Item -ItemType Directory -Force $ResultsDir | Out-Null

$toolList   = if ($Tool   -eq "all") { $AllTools }                          else { @($Tool) }
$targetList = if ($Target -eq "all") { @("vulnerable-shop","juice-shop") }  else { @($Target) }
$runList    = if ($Run    -gt 0)    { @($Run) }                             else { 1..$Runs }

$needsDast = @($toolList | Where-Object { $DastTools -contains $_ }).Count -gt 0

Write-Host ""
Write-Host "+==================================================================+" -ForegroundColor White
Write-Host "|   BA Security Benchmark -- lokaler Runner                        |" -ForegroundColor White
Write-Host "+==================================================================+" -ForegroundColor White
Write-Host "  Tools:    $($toolList -join ', ')"
Write-Host "  Targets:  $($targetList -join ', ')"
Write-Host "  Runs:     $($runList -join ', ')"
Write-Host "  Output:   $ResultsDir"
Write-Host "  Timing:   $TimingFile"
Write-Host ""

if (-not $SkipStartup -and $needsDast) {
    Write-Host "  Starte Ziel-Applikationen..." -ForegroundColor Cyan
    foreach ($t in $targetList) { Start-AppTarget $t }
} elseif ($SkipStartup) {
    Log-Step "-SkipStartup gesetzt -- Targets werden nicht gestartet."
} else {
    Log-Step "Keine DAST-Tools im Einsatz -- Targets müssen nicht laufen."
}

$total  = @($toolList).Count * @($targetList).Count * @($runList).Count
$done   = 0
$failed = [System.Collections.Generic.List[string]]::new()

foreach ($t in $targetList) {
    foreach ($tl in $toolList) {
        foreach ($r in $runList) {
            $done++
            Write-Host "`n  [$done/$total]" -ForegroundColor DarkGray -NoNewline
            $ok = Invoke-Tool $tl $t $r
            if (-not $ok) { $failed.Add("${tl}/${t}/run${r}") }
            Start-Sleep 2
        }
    }
}

$allOk = $failed.Count -eq 0
$summaryColor = if ($allOk) { "Green" } else { "Yellow" }

Write-Host ""
Write-Host "+==================================================================+" -ForegroundColor $summaryColor
Write-Host "|   BENCHMARK ABGESCHLOSSEN                                        |" -ForegroundColor $summaryColor
Write-Host "+==================================================================+" -ForegroundColor $summaryColor
Write-Host "  Runs gesamt:    $total"
Write-Host "  Erfolgreich:    $($total - $failed.Count)"
Write-Host "  Fehlgeschlagen: $($failed.Count)"
Write-Host "  Ergebnisse:     $ResultsDir"
Write-Host "  Timing-Log:     $TimingFile"

if ($failed.Count -gt 0) {
    Write-Host ""
    Write-Host "  Fehlgeschlagene Runs:" -ForegroundColor Yellow
    $failed | ForEach-Object { Write-Host "    [XX] $_" -ForegroundColor Yellow }
}

Write-Host ""
Write-Host "  Nächste Schritte:" -ForegroundColor Cyan
Write-Host "    python analysis/convert_to_sarif.py   # Nicht-SARIF-Outputs konvertieren"
Write-Host "    python analysis/match_results.py      # Ground-Truth-Matching (FF1)"
Write-Host "    python analysis/calculate_metrics.py  # Recall, Precision, F1, Youden"
Write-Host ""
