# One-command check: attack suite + URL smoke test. Run from anywhere:
#   powershell -ExecutionPolicy Bypass -File scripts\check.ps1
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$py = if (Test-Path ".venv\Scripts\python.exe") { ".venv\Scripts\python.exe" } else { "python" }

$server = Start-Process -FilePath $py -ArgumentList "-m","uvicorn","backend.app.main:app","--host","127.0.0.1","--port","8000" -PassThru -WindowStyle Hidden
try {
    $ok = $false
    for ($i = 0; $i -lt 30; $i++) {
        Start-Sleep -Milliseconds 500
        try { Invoke-WebRequest "http://127.0.0.1:8000/api/users" -UseBasicParsing -TimeoutSec 2 | Out-Null; $ok = $true; break } catch {}
    }
    if (-not $ok) { throw "Server did not start on port 8000 (is another one already running?)" }

    foreach ($u in "/", "/v1/", "/v2/", "/shared/crypto.js", "/shared/dlp.js", "/shared/vendor/libsodium.js") {
        $code = (Invoke-WebRequest "http://127.0.0.1:8000$u" -UseBasicParsing -TimeoutSec 5).StatusCode
        Write-Output "$u -> $code"
        if ($code -ne 200) { throw "$u returned $code" }
    }

    & $py attacks\run_all_attacks.py
    if ($LASTEXITCODE -ne 0) { throw "Attack suite failed" }
    Write-Output "CHECK PASSED"
}
finally {
    Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
}
