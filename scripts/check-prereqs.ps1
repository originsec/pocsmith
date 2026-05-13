#Requires -Version 5.1
<#
.SYNOPSIS
    Verify all pocsmith prerequisites are present on this host.
.DESCRIPTION
    Checks Python, Hyper-V, Debugging Tools (kd.exe), Visual Studio,
    Java, Ghidra, and required environment variables.
    Prints [+] pass or [X] fail for each item. Exits 0 if all pass, 1 if any fail.
#>

[CmdletBinding()]
param(
    [string]$Config   = "",
    [string]$VenvPath = ""
)

# Resolve venv: explicit --VenvPath wins, then auto-detect .venv in the repo root,
# then fall back to system python.
if (-not $VenvPath) {
    $autoVenv = Join-Path (Split-Path $PSScriptRoot -Parent) ".venv"
    if (Test-Path (Join-Path $autoVenv "Scripts\python.exe")) { $VenvPath = $autoVenv }
}
$checkPython = "python"
if ($VenvPath) {
    $venvPy = Join-Path $VenvPath "Scripts\python.exe"
    if (Test-Path $venvPy) { $checkPython = $venvPy }
}

$pass = 0
$fail = 0

function Check-Pass([string]$label, [string]$detail = "") {
    $msg = "[+] $label"
    if ($detail) { $msg += "  ($detail)" }
    Write-Host $msg -ForegroundColor Green
    $script:pass++
}

function Check-Fail([string]$label, [string]$hint = "") {
    $msg = "[X] $label"
    if ($hint) { $msg += "  -- $hint" }
    Write-Host $msg -ForegroundColor Red
    $script:fail++
}

Write-Host "`n=== pocsmith prerequisite check ===`n"

# ---- Resolve credentials: YAML values take priority, env vars are fallback ----
# Values are populated from the config if --Config is supplied; empty string means
# the check will fall back to the corresponding environment variable.
$apiKeyVal    = ""
$guestUserVal = ""
$guestPassVal = ""
$ghidraMode   = ""

if ($Config) {
    if (-not (Test-Path $Config)) {
        Write-Host "[!] --Config path not found: $Config" -ForegroundColor Yellow
    } else {
        $pyScript = @"
import sys, yaml, os
from pathlib import Path
config_path = sys.argv[1]
with open(config_path) as f:
    d = yaml.safe_load(f)
try:
    from dotenv import load_dotenv
    load_dotenv(Path(config_path).parent / '.env')
except ImportError:
    pass
llm    = d.get('llm', {})
hv     = d.get('hyperv_guest', {})
ghidra = d.get('ghidra', {})
api_key_env      = llm.get('api_key_env', 'ANTHROPIC_API_KEY')
username_env     = hv.get('username_env', 'HYPERV_GUEST_USERNAME')
password_env     = hv.get('password_env', 'HYPERV_GUEST_PASSWORD')
print(os.environ.get(api_key_env, '') or '')
print(os.environ.get(username_env, '') or '')
print(os.environ.get(password_env, '') or '')
print(ghidra.get('mode', 'local'))
"@
        $result = & $checkPython -c $pyScript $Config 2>&1
        if ($LASTEXITCODE -eq 0) {
            $lines = $result -split "`n" | ForEach-Object { $_.Trim() }
            # pad to 4 entries so indexing is safe
            while ($lines.Count -lt 4) { $lines += "" }
            $apiKeyVal    = $lines[0]
            $guestUserVal = $lines[1]
            $guestPassVal = $lines[2]
            $ghidraMode   = $lines[3]
            Write-Host "[*] Config loaded from $Config`n"
        } else {
            Write-Host "[!] Failed to parse config (is pyyaml installed in the venv?): $result" -ForegroundColor Yellow
            # Still try to load .env from the config's directory so credential checks work
            $configEnv = Join-Path (Split-Path (Resolve-Path $Config) -Parent) ".env"
            if (Test-Path $configEnv) {
                Get-Content $configEnv | ForEach-Object {
                    if ($_ -match '^\s*([A-Za-z_][A-Za-z0-9_]*)=(.*)$') {
                        $k = $Matches[1]; $v = $Matches[2].Trim('"').Trim("'")
                        if (-not [Environment]::GetEnvironmentVariable($k, 'Process')) {
                            [Environment]::SetEnvironmentVariable($k, $v, 'Process')
                        }
                    }
                }
            }
        }
    }
}

# Load .env from the repo root (script's parent) or cwd when no --Config was given.
# This ensures credentials set in .env are visible even without a full config file.
if (-not $Config) {
    $envCandidates = @(
        (Join-Path (Split-Path $PSScriptRoot -Parent) ".env"),
        (Join-Path (Get-Location).Path ".env")
    )
    $envFile = $envCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    if ($envFile) {
        Get-Content $envFile | ForEach-Object {
            if ($_ -match '^\s*([A-Za-z_][A-Za-z0-9_]*)=(.*)$') {
                $k = $Matches[1]
                $v = $Matches[2].Trim('"').Trim("'")
                if (-not [Environment]::GetEnvironmentVariable($k, 'Process')) {
                    [Environment]::SetEnvironmentVariable($k, $v, 'Process')
                }
            }
        }
    }
}

# Fall back to environment variables when config is not supplied
if (-not $apiKeyVal)    { $apiKeyVal    = $env:ANTHROPIC_API_KEY }
if (-not $guestUserVal) { $guestUserVal = $env:HYPERV_GUEST_USERNAME }
if (-not $guestPassVal) { $guestPassVal = $env:HYPERV_GUEST_PASSWORD }

# ---- Python 3.12+ ----
try {
    $pyVer = & python --version 2>&1
    if ($pyVer -match "Python (\d+)\.(\d+)") {
        $maj = [int]$Matches[1]; $min = [int]$Matches[2]
        if ($maj -gt 3 -or ($maj -eq 3 -and $min -ge 12)) {
            Check-Pass "Python $maj.$min"
        } else {
            Check-Fail "Python $maj.$min" "need 3.12 or newer"
        }
    } else {
        Check-Fail "Python" "could not parse version from: $pyVer"
    }
} catch {
    Check-Fail "Python" "not found on PATH"
}

# ---- Hyper-V ----
# Get-VMHost works for Hyper-V Administrators without UAC elevation.
# Get-WindowsOptionalFeature -Online requires full elevation; try it only as fallback.
$hvOk = $false
try {
    $vmHost = Get-VMHost -ErrorAction Stop
    if ($vmHost) { $hvOk = $true; Check-Pass "Hyper-V (Get-VMHost ok)" }
} catch { }

if (-not $hvOk) {
    try {
        $hvFeature = Get-WindowsOptionalFeature -Online -FeatureName "Microsoft-Hyper-V-All" -ErrorAction Stop
        if ($hvFeature -and $hvFeature.State -eq "Enabled") {
            Check-Pass "Hyper-V enabled"
        } else {
            Check-Fail "Hyper-V" "enable with: Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All"
        }
    } catch {
        Check-Fail "Hyper-V" "could not query -- add your user to Hyper-V Administrators and log out/in, or run elevated"
    }
}

# ---- Debugging Tools for Windows (kd.exe) ----
$kdPaths = @(
    "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\kd.exe",
    "C:\Program Files\Windows Kits\10\Debuggers\x64\kd.exe"
)
$kdFound = $kdPaths | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($kdFound) {
    Check-Pass "Debugging Tools (kd.exe)" $kdFound
} else {
    Check-Fail "Debugging Tools (kd.exe)" "install Windows SDK with Debugging Tools; expected at $($kdPaths[0])"
}

# ---- Visual Studio / Build Tools vcvarsall ----
$vcPaths = @(
    "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat",
    "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvarsall.bat",
    "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsall.bat",
    "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat"
)
$vcFound = $vcPaths | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($vcFound) {
    Check-Pass "Visual Studio vcvarsall" $vcFound
} else {
    Check-Fail "Visual Studio 2022" "install VS 2022 with 'Desktop Development with C++' workload, or VS Build Tools 2022 (winget install Microsoft.VisualStudio.2022.BuildTools)"
}

# ---- Ghidra (mode-aware) ----
# Only check Ghidra prerequisites when the mode is known from --Config.
# Without a config we can't know whether the user will use docker or local mode.
if (-not $ghidraMode) {
    Write-Host "[~] Ghidra: skipped -- pass --Config pocsmith.yaml to check mode-specific prerequisites" -ForegroundColor DarkGray
} elseif ($ghidraMode -eq "docker") {
    # Docker mode: just need Docker accessible
    $dockerExe = $null
    $dockerCmd = Get-Command docker -ErrorAction SilentlyContinue
    if ($dockerCmd) {
        $dockerExe = $dockerCmd.Source
    } else {
        $dockerFallbacks = @(
            "C:\Program Files\Docker\Docker\resources\bin\docker.exe",
            "C:\Program Files\Docker\resources\bin\docker.exe",
            "$env:LOCALAPPDATA\Docker\wsl\distro\usr\bin\docker"
        )
        $dockerExe = $dockerFallbacks | Where-Object { Test-Path $_ } | Select-Object -First 1
    }

    if ($dockerExe) {
        $null = & $dockerExe version 2>&1
        if ($LASTEXITCODE -eq 0) {
            Check-Pass "Docker (ghidra.mode=docker)" $dockerExe
        } else {
            Check-Fail "Docker" "daemon not running; start Docker Desktop"
        }
    } else {
        Check-Fail "Docker" "not found; install Docker Desktop"
    }
} else {
    # Local mode: need Java 21+ and a Ghidra install
    try {
        $javaVer = & java -version 2>&1 | Select-Object -First 1
        if ($javaVer -match "version `"?(\d+)") {
            $jMaj = [int]$Matches[1]
            if ($jMaj -ge 21) {
                Check-Pass "Java $jMaj"
            } else {
                Check-Fail "Java $jMaj" "Ghidra requires Java 21+; get from adoptium.net"
            }
        } else {
            Check-Fail "Java" "could not parse version"
        }
    } catch {
        Check-Fail "Java" "not found on PATH; get from adoptium.net"
    }

    $ghidraInstallDir = $env:GHIDRA_INSTALL_DIR
    if ($ghidraInstallDir -and (Test-Path "$ghidraInstallDir\ghidraRun.bat")) {
        Check-Pass "Ghidra" $ghidraInstallDir
    } else {
        $ghidraCommon = @("C:\Tools\ghidra_11.3", "C:\Tools\Ghidra", "C:\ghidra")
        $ghidraFound = $ghidraCommon | Where-Object { Test-Path "$_\ghidraRun.bat" } | Select-Object -First 1
        if ($ghidraFound) {
            Check-Pass "Ghidra" "$ghidraFound (set GHIDRA_INSTALL_DIR=$ghidraFound)"
        } else {
            Check-Fail "Ghidra" "set GHIDRA_INSTALL_DIR or install to C:\Tools\ghidra_11.x"
        }
    }
}

# ---- mcp (kd-mcp dependency) ----
try {
    $null = & $checkPython -c "import mcp" 2>&1
    if ($LASTEXITCODE -eq 0) {
        Check-Pass "mcp (kd-mcp dep)"
    } else {
        Check-Fail "mcp" "pip install mcp"
    }
} catch {
    Check-Fail "mcp" "pip install mcp"
}

# ---- claude-agent-sdk ----
try {
    $null = & $checkPython -c "import claude_agent_sdk" 2>&1
    if ($LASTEXITCODE -eq 0) {
        Check-Pass "claude-agent-sdk"
    } else {
        Check-Fail "claude-agent-sdk" "pip install claude-agent-sdk"
    }
} catch {
    Check-Fail "claude-agent-sdk" "pip install claude-agent-sdk"
}

# ---- pocsmith package ----
try {
    $null = & $checkPython -c "import pocsmith" 2>&1
    if ($LASTEXITCODE -eq 0) {
        Check-Pass "pocsmith package installed"
    } else {
        Check-Fail "pocsmith" "cd to repo root and run: pip install -e ."
    }
} catch {
    Check-Fail "pocsmith" "cd to repo root and run: pip install -e ."
}

# ---- Credentials (yaml values or env var fallback) ----
if ($apiKeyVal) {
    Check-Pass "ANTHROPIC_API_KEY"
} else {
    Check-Fail "ANTHROPIC_API_KEY" "set ANTHROPIC_API_KEY in a .env file or as an environment variable"
}

if ($guestUserVal) {
    Check-Pass "Hyper-V guest username"
} else {
    Check-Fail "Hyper-V guest username" "set HYPERV_GUEST_USERNAME in .env or as an environment variable"
}

if ($guestPassVal) {
    Check-Pass "Hyper-V guest password"
} else {
    Check-Fail "Hyper-V guest password" "set HYPERV_GUEST_PASSWORD in .env or as an environment variable"
}

# ---- Summary ----
Write-Host "`n=== Results: $pass passed, $fail failed ===`n"
if ($fail -gt 0) { exit 1 } else { exit 0 }
