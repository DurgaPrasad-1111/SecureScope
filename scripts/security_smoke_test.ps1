param(
    [string]$BaseUrl = "http://127.0.0.1:8000/api/v1",
    [string]$HealthUrl = "http://127.0.0.1:8000/health",
    [string]$AdminEmail = "admin@securescope.app",
    [string]$AdminPassword = "SecureScope@Admin@Password!",
    [string]$TargetDomain = "example.com",
    [switch]$SkipScan,
    [switch]$ClearAtEnd
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:Results = @()

function Add-Result {
    param(
        [string]$Name,
        [bool]$Pass,
        [string]$Detail
    )

    $script:Results += [pscustomobject]@{
        Test   = $Name
        Status = if ($Pass) { 'PASS' } else { 'FAIL' }
        Detail = $Detail
    }

    if ($Pass) {
        Write-Host "[PASS] $Name - $Detail" -ForegroundColor Green
    } else {
        Write-Host "[FAIL] $Name - $Detail" -ForegroundColor Red
    }
}

function Get-StatusCodeFromError {
    param([System.Management.Automation.ErrorRecord]$Err)
    try {
        if ($Err.Exception -and $Err.Exception.Response -and $Err.Exception.Response.StatusCode) {
            return [int]$Err.Exception.Response.StatusCode
        }
    } catch {
    }
    return -1
}

function Try-LoadDotEnv {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return }

    Get-Content $Path | ForEach-Object {
        $line = $_.Trim()
        if (-not $line -or $line.StartsWith('#')) { return }
        $parts = $line -split '=', 2
        if ($parts.Count -ne 2) { return }

        $k = $parts[0].Trim()
        $v = $parts[1].Trim()
        switch ($k) {
            'INITIAL_ADMIN_EMAIL' {
                if ($AdminEmail -eq 'admin@securescope.app') { $script:AdminEmail = $v }
            }
            'INITIAL_ADMIN_PASSWORD' {
                if ($AdminPassword -eq 'SecureScope@Admin@Password!') { $script:AdminPassword = $v }
            }
        }
    }
}

$root = Split-Path -Parent $PSScriptRoot
$envPath = Join-Path $root '.env'
Try-LoadDotEnv -Path $envPath

Write-Host "Running SecureScope security smoke tests..." -ForegroundColor Cyan
Write-Host "Base URL: $BaseUrl" -ForegroundColor Cyan
Write-Host "Health URL: $HealthUrl" -ForegroundColor Cyan
Write-Host "Admin Email: $AdminEmail" -ForegroundColor Cyan

$accessToken = $null
$refreshToken = $null
$csrfToken = $null

# 1) Health check
try {
    $health = Invoke-RestMethod -Uri $HealthUrl -Method Get
    Add-Result -Name 'Health endpoint' -Pass ($health.status -eq 'ok') -Detail ("status=" + $health.status)
} catch {
    Add-Result -Name 'Health endpoint' -Pass $false -Detail $_.Exception.Message
}

# 2) Valid login
try {
    $loginBody = @{ email = $AdminEmail; password = $AdminPassword } | ConvertTo-Json
    $loginRes = Invoke-RestMethod -Uri "$BaseUrl/auth/login" -Method Post -Body $loginBody -ContentType 'application/json'
    $accessToken = $loginRes.access_token
    $refreshToken = $loginRes.refresh_token
    $csrfToken = $loginRes.csrf_token

    $ok = -not [string]::IsNullOrWhiteSpace($accessToken) -and -not [string]::IsNullOrWhiteSpace($csrfToken)
    Add-Result -Name 'Valid login' -Pass $ok -Detail 'access/refresh/csrf tokens returned'
} catch {
    Add-Result -Name 'Valid login' -Pass $false -Detail $_.Exception.Message
}

# 3) Invalid login
try {
    $badLoginBody = @{ email = $AdminEmail; password = 'wrong-password-123' } | ConvertTo-Json
    Invoke-RestMethod -Uri "$BaseUrl/auth/login" -Method Post -Body $badLoginBody -ContentType 'application/json' | Out-Null
    Add-Result -Name 'Invalid login rejection' -Pass $false -Detail 'Expected 401 but request succeeded'
} catch {
    $code = Get-StatusCodeFromError -Err $_
    Add-Result -Name 'Invalid login rejection' -Pass ($code -eq 401) -Detail ("HTTP $code")
}

# 4) Protected route without token
try {
    Invoke-RestMethod -Uri "$BaseUrl/users/me" -Method Get | Out-Null
    Add-Result -Name 'Protected route without token' -Pass $false -Detail 'Expected 401 but request succeeded'
} catch {
    $code = Get-StatusCodeFromError -Err $_
    Add-Result -Name 'Protected route without token' -Pass ($code -eq 401) -Detail ("HTTP $code")
}

if (-not $accessToken) {
    Write-Host "Cannot continue tests without access token." -ForegroundColor Red
    exit 1
}

$authHeaders = @{ Authorization = "Bearer $accessToken" }
$csrfHeaders = @{ Authorization = "Bearer $accessToken"; 'X-CSRF-Token' = $csrfToken }

# 5) Authenticated profile endpoint
try {
    $me = Invoke-RestMethod -Uri "$BaseUrl/users/me" -Method Get -Headers $authHeaders
    $ok = -not [string]::IsNullOrWhiteSpace($me.email) -and -not [string]::IsNullOrWhiteSpace($me.role)
    Add-Result -Name 'Authenticated /users/me' -Pass $ok -Detail ("email=" + $me.email + ", role=" + $me.role)
} catch {
    Add-Result -Name 'Authenticated /users/me' -Pass $false -Detail $_.Exception.Message
}

# 6) CSRF enforcement on state-changing endpoint
try {
    $scanPayload = @{ domain = $TargetDomain; modules = @('port_scan') } | ConvertTo-Json
    Invoke-RestMethod -Uri "$BaseUrl/scans/" -Method Post -Headers $authHeaders -Body $scanPayload -ContentType 'application/json' | Out-Null
    Add-Result -Name 'CSRF enforcement on POST /scans' -Pass $false -Detail 'Expected 403 without CSRF token'
} catch {
    $code = Get-StatusCodeFromError -Err $_
    Add-Result -Name 'CSRF enforcement on POST /scans' -Pass ($code -eq 403) -Detail ("HTTP $code")
}

# 7) Input validation (malicious domain should fail)
try {
    $badDomainPayload = @{ domain = "' OR 1=1--"; modules = @('port_scan') } | ConvertTo-Json
    Invoke-RestMethod -Uri "$BaseUrl/scans/" -Method Post -Headers $csrfHeaders -Body $badDomainPayload -ContentType 'application/json' | Out-Null
    Add-Result -Name 'Input validation for domain' -Pass $false -Detail 'Expected validation failure but request succeeded'
} catch {
    $code = Get-StatusCodeFromError -Err $_
    Add-Result -Name 'Input validation for domain' -Pass ($code -eq 422) -Detail ("HTTP $code")
}

# 8) Run valid scan and verify response
if ($SkipScan) {
    Add-Result -Name 'Run valid scan' -Pass $true -Detail 'Skipped by flag'
} else {
    try {
        $fullPayload = @{
            domain = $TargetDomain
            modules = @(
                'port_scan',
                'subdomain_enum',
                'dns_records',
                'tls_check',
                'header_validation',
                'tech_fingerprint',
                'osint_metadata'
            )
        } | ConvertTo-Json -Depth 4

        $scanRes = Invoke-RestMethod -Uri "$BaseUrl/scans/" -Method Post -Headers $csrfHeaders -Body $fullPayload -ContentType 'application/json'
        $ok = ($scanRes.status -eq 'completed' -or $scanRes.status -eq 'running') -and ($scanRes.risk_score -ge 0)
        Add-Result -Name 'Run valid scan' -Pass $ok -Detail ("scan_id=" + $scanRes.id + ", risk=" + $scanRes.risk_score)
    } catch {
        Add-Result -Name 'Run valid scan' -Pass $false -Detail $_.Exception.Message
    }
}

# 9) Scan history accessibility
try {
    $history = Invoke-RestMethod -Uri "$BaseUrl/scans/" -Method Get -Headers $authHeaders
    $count = @($history).Count
    Add-Result -Name 'Scan history endpoint' -Pass $true -Detail ("rows=" + $count)
} catch {
    Add-Result -Name 'Scan history endpoint' -Pass $false -Detail $_.Exception.Message
}

# 10) Reports listing
$reports = @()
try {
    $reports = Invoke-RestMethod -Uri "$BaseUrl/reports/" -Method Get -Headers $authHeaders
    $count = @($reports).Count
    Add-Result -Name 'Reports listing' -Pass $true -Detail ("rows=" + $count)
} catch {
    Add-Result -Name 'Reports listing' -Pass $false -Detail $_.Exception.Message
}

# 11) Report download check (if at least one report exists)
if (@($reports).Count -gt 0) {
    try {
        $rid = $reports[0].id
        $sid = $reports[0].scan_id
        $tmp = Join-Path $env:TEMP ("securescope_test_report_" + [Guid]::NewGuid().ToString() + ".pdf")
        Invoke-WebRequest -Uri "$BaseUrl/reports/$rid/download" -Method Get -Headers $authHeaders -OutFile $tmp | Out-Null
        $size = (Get-Item $tmp).Length
        Remove-Item $tmp -Force
        Add-Result -Name 'Report download' -Pass ($size -gt 100) -Detail ("scan_id=" + $sid + ", bytes=" + $size)
    } catch {
        Add-Result -Name 'Report download' -Pass $false -Detail $_.Exception.Message
    }
} else {
    Add-Result -Name 'Report download' -Pass $true -Detail 'Skipped (no reports available)'
}

# 12) Clear scans endpoint with CSRF (scope-aware)
if ($ClearAtEnd) {
    try {
        $clearRes = Invoke-RestMethod -Uri "$BaseUrl/scans/" -Method Delete -Headers $csrfHeaders
        $detail = if ($clearRes.scope) { "$($clearRes.detail) [scope=$($clearRes.scope)]" } else { $clearRes.detail }
        Add-Result -Name 'Clear scans endpoint' -Pass $true -Detail $detail
    } catch {
        Add-Result -Name 'Clear scans endpoint' -Pass $false -Detail $_.Exception.Message
    }
} else {
    Add-Result -Name 'Clear scans endpoint' -Pass $true -Detail 'Skipped (use -ClearAtEnd to enable destructive cleanup)'
}

# 13) Refresh token flow
try {
    $refreshBody = @{ refresh_token = $refreshToken } | ConvertTo-Json
    $refreshRes = Invoke-RestMethod -Uri "$BaseUrl/auth/refresh" -Method Post -Body $refreshBody -ContentType 'application/json'
    $ok = -not [string]::IsNullOrWhiteSpace($refreshRes.access_token)
    Add-Result -Name 'Refresh token flow' -Pass $ok -Detail 'new access token returned'
} catch {
    Add-Result -Name 'Refresh token flow' -Pass $false -Detail $_.Exception.Message
}

# Summary
$passCount = @($script:Results | Where-Object { $_.Status -eq 'PASS' }).Count
$failCount = @($script:Results | Where-Object { $_.Status -eq 'FAIL' }).Count

Write-Host "`n========== SUMMARY ==========" -ForegroundColor Cyan
$script:Results | Format-Table -AutoSize
Write-Host "Passed: $passCount" -ForegroundColor Green
Write-Host "Failed: $failCount" -ForegroundColor Red

if ($failCount -gt 0) {
    exit 1
}

exit 0
