#Requires -Version 5.1
<#
.SYNOPSIS
    One-shot setup for pocsmith on a new research host.
.DESCRIPTION
    1. Verifies hard prerequisites (Python 3.12+, Hyper-V, Debugging Tools).
    2. Creates the pocsmith venv and installs all runtime dependencies into it.
    3. Installs the pocsmith package in editable mode into the same venv.
    4. Clones hyperv-mcp and kd-mcp next to the pocsmith repo and installs them into the venv.
    5. Provisions the workspace root: attacker venv (impacket) and Sysinternals Suite.
    6. Writes pocsmith.yaml if it does not exist.
    7. Prints a checklist of remaining manual steps.
.PARAMETER RepoRoot
    Path to the cloned pocsmith repo. Defaults to the parent of this script.
.PARAMETER PocsmithVenv
    Where to create the pocsmith Python venv. Default: .venv inside the repo root.
.PARAMETER WorkspaceRoot
    Root directory for pocsmith runtime data: per-CVE workspaces, attacker
    venv, sysinternals tools. Default: C:\Research\pocsmith-workspaces.
.PARAMETER AttackerVenv
    Where to create the attacker Python venv. Default: <WorkspaceRoot>\attacker-venv.
.PARAMETER SysinternalsDir
    Where to stage the Sysinternals Suite. Default: <WorkspaceRoot>\sysinternals.
.PARAMETER HypervMcpRoot
    Where to clone hyperv-mcp. Default: sibling of the pocsmith repo (<RepoRoot>\..\hyperv-mcp).
.PARAMETER KdMcpRoot
    Where to clone kd-mcp. Default: sibling of the pocsmith repo (<RepoRoot>\..\kd-mcp).
.PARAMETER HypervMcpRepo
    Git URL for hyperv-mcp. Default: https://github.com/originsec/hyperv-mcp.git
.PARAMETER KdMcpRepo
    Git URL for kd-mcp. Default: https://github.com/originsec/kd-mcp.git
.PARAMETER SysinternalsUrl
    URL to the Sysinternals Suite zip. Default: official download.sysinternals.com URL.
.PARAMETER SkipVenv
    Skip creating both venvs (useful if already set up).
.PARAMETER SkipMcp
    Skip cloning and installing the MCP server repos.
.PARAMETER SkipSysinternals
    Skip downloading the Sysinternals Suite.
#>

[CmdletBinding()]
param(
    [string]$RepoRoot        = (Split-Path $PSScriptRoot -Parent),
    [string]$PocsmithVenv    = "",
    [string]$WorkspaceRoot   = "C:\Research\pocsmith-workspaces",
    [string]$AttackerVenv    = "",
    [string]$SysinternalsDir = "",
    [string]$HypervMcpRoot   = "",
    [string]$KdMcpRoot       = "",
    [string]$HypervMcpRepo   = "https://github.com/originsec/hyperv-mcp.git",
    [string]$KdMcpRepo       = "https://github.com/originsec/kd-mcp.git",
    [string]$SysinternalsUrl = "https://download.sysinternals.com/files/SysinternalsSuite.zip",
    [switch]$SkipVenv,
    [switch]$SkipMcp,
    [switch]$SkipSysinternals
)

# Default venv to .venv inside the repo root, resolved after $RepoRoot is known
if (-not $PocsmithVenv) { $PocsmithVenv = Join-Path $RepoRoot ".venv" }

# Default workspace-scoped tools to live under WorkspaceRoot (override via params).
if (-not $AttackerVenv)    { $AttackerVenv    = Join-Path $WorkspaceRoot "attacker-venv" }
if (-not $SysinternalsDir) { $SysinternalsDir = Join-Path $WorkspaceRoot "sysinternals" }

# Default MCP repos to siblings of the pocsmith repo. Override via -HypervMcpRoot
# / -KdMcpRoot if you want them somewhere else.
$RepoParent = Split-Path $RepoRoot -Parent
if (-not $HypervMcpRoot) { $HypervMcpRoot = Join-Path $RepoParent "hyperv-mcp" }
if (-not $KdMcpRoot)     { $KdMcpRoot     = Join-Path $RepoParent "kd-mcp" }

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step([string]$msg) {
    Write-Host "`n[*] $msg" -ForegroundColor Cyan
}

function Write-Ok([string]$msg) {
    Write-Host "    [+] $msg" -ForegroundColor Green
}

function Write-Warn([string]$msg) {
    Write-Host "    [!] $msg" -ForegroundColor Yellow
}

function Fail([string]$msg) {
    Write-Host "`n[X] FATAL: $msg" -ForegroundColor Red
    exit 1
}

# ---------------------------------------------------------------------------
# 1. Hard prerequisite checks
# ---------------------------------------------------------------------------
Write-Step "Checking hard prerequisites"

# Python 3.12+
try {
    $pyVer = & python --version 2>&1
    if ($pyVer -match "Python (\d+)\.(\d+)") {
        $maj = [int]$Matches[1]; $min = [int]$Matches[2]
        if ($maj -lt 3 -or ($maj -eq 3 -and $min -lt 12)) {
            Fail "Python $maj.$min found but 3.12+ is required."
        }
        Write-Ok "Python $maj.$min"
    } else {
        Fail "Could not determine Python version: $pyVer"
    }
} catch {
    Fail "python not found on PATH. Install from python.org."
}

# git
try {
    $null = & git --version 2>&1
    Write-Ok "git"
} catch {
    Fail "git not found on PATH."
}

# Debugging Tools (kd.exe) -- required by kd-mcp
$kdPaths = @(
    "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\kd.exe",
    "C:\Program Files\Windows Kits\10\Debuggers\x64\kd.exe"
)
$kdFound = $kdPaths | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $kdFound) {
    Fail "Debugging Tools for Windows not found. Install the Windows SDK with the 'Debugging Tools for Windows' component."
}
Write-Ok "Debugging Tools: $kdFound"

# Hyper-V -- check module presence first, then permission separately
if (-not (Get-Module -ListAvailable -Name Hyper-V)) {
    Write-Warn "Hyper-V PowerShell module not found. Enable Hyper-V via:"
    Write-Warn "  Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All"
} else {
    try {
        $null = Get-VM -ErrorAction Stop
        Write-Ok "Hyper-V (permissions OK)"
    } catch {
        Write-Warn "Hyper-V module found but Get-VM failed -- group membership may not be active yet."
        Write-Warn "You must fully log out of Windows and log back in after joining Hyper-V Administrators."
        Write-Warn "Closing and reopening a terminal is not enough; the login token must be refreshed."
    }
}

# ---------------------------------------------------------------------------
# 2. Create pocsmith venv and install dependencies
# ---------------------------------------------------------------------------
Write-Step "Creating pocsmith venv at $PocsmithVenv"

if (-not $SkipVenv) {
    if (-not (Test-Path $PocsmithVenv)) {
        & python -m venv $PocsmithVenv
        if ($LASTEXITCODE -ne 0) { Fail "venv creation failed at $PocsmithVenv." }
        Write-Ok "Venv created at $PocsmithVenv"
    } else {
        Write-Warn "Venv already exists at $PocsmithVenv -- reusing"
    }
}

$venvPip    = "$PocsmithVenv\Scripts\pip.exe"
$venvPython = "$PocsmithVenv\Scripts\python.exe"

if (-not (Test-Path $venvPip)) {
    Fail "pip not found at $venvPip -- venv may be incomplete. Delete it and re-run."
}

$packages = @(
    "mcp",                # MCP protocol library
    "claude-agent-sdk",   # Anthropic Agent SDK
    "pydantic>=2.6",
    "pyyaml>=6.0",
    "typer>=0.12",
    "python-dotenv>=1.0",
    "rich>=13.7"
)

foreach ($pkg in $packages) {
    Write-Host "    pip install $pkg" -ForegroundColor DarkGray
    & $venvPip install --quiet $pkg
    if ($LASTEXITCODE -ne 0) { Fail "pip install $pkg failed. Check error output above." }
}
Write-Ok "All packages installed in $PocsmithVenv"

# ---------------------------------------------------------------------------
# 4. Install pocsmith in editable mode into the venv
# ---------------------------------------------------------------------------
Write-Step "Installing pocsmith package (editable) into venv"

Push-Location $RepoRoot
try {
    & $venvPip install --quiet -e ".[dev]"
    if ($LASTEXITCODE -ne 0) { Fail "pip install -e .[dev] failed." }
    Write-Ok "pocsmith installed from $RepoRoot"
} finally {
    Pop-Location
}

# ---------------------------------------------------------------------------
# 3b. Clone and install MCP server repos (hyperv-mcp, kd-mcp)
# ---------------------------------------------------------------------------
function Install-McpRepo {
    param(
        [string]$Name,
        [string]$RepoUrl,
        [string]$Dest,
        [string]$VenvPip
    )

    Write-Step "Setting up $Name at $Dest"

    if (Test-Path $Dest) {
        if (Test-Path (Join-Path $Dest ".git")) {
            Write-Warn "$Dest already exists -- reusing (run 'git -C $Dest pull' to update)"
        } else {
            Write-Warn "$Dest exists but is not a git checkout -- skipping clone"
        }
    } else {
        $DestParent = Split-Path $Dest -Parent
        if (-not (Test-Path $DestParent)) {
            New-Item -ItemType Directory -Path $DestParent -Force | Out-Null
        }
        & git clone $RepoUrl $Dest
        if ($LASTEXITCODE -ne 0) { Fail "git clone $RepoUrl failed." }
        Write-Ok "Cloned $RepoUrl"
    }

    Push-Location $Dest
    try {
        if (Test-Path "pyproject.toml") {
            & $VenvPip install --quiet -e "."
            if ($LASTEXITCODE -ne 0) { Fail "pip install -e $Dest failed." }
            Write-Ok "$Name installed into venv (editable)"
        } elseif (Test-Path "requirements.txt") {
            & $VenvPip install --quiet -r "requirements.txt"
            if ($LASTEXITCODE -ne 0) { Fail "pip install -r requirements.txt for $Name failed." }
            Write-Ok "$Name requirements.txt installed into venv"
        } else {
            Write-Warn "$Name has no pyproject.toml or requirements.txt -- nothing to install"
        }
    } finally {
        Pop-Location
    }
}

if ($SkipMcp) {
    Write-Step "Skipping MCP server clone (-SkipMcp)"
} else {
    Install-McpRepo -Name "hyperv-mcp" -RepoUrl $HypervMcpRepo -Dest $HypervMcpRoot -VenvPip $venvPip
    Install-McpRepo -Name "kd-mcp"     -RepoUrl $KdMcpRepo     -Dest $KdMcpRoot     -VenvPip $venvPip
}

# ---------------------------------------------------------------------------
# 4a. Ensure WorkspaceRoot exists (parent of attacker venv + sysinternals)
# ---------------------------------------------------------------------------
Write-Step "Provisioning workspace root at $WorkspaceRoot"
if (-not (Test-Path $WorkspaceRoot)) {
    New-Item -ItemType Directory -Path $WorkspaceRoot -Force | Out-Null
    Write-Ok "Created $WorkspaceRoot"
} else {
    Write-Ok "$WorkspaceRoot already exists"
}

# ---------------------------------------------------------------------------
# 4b. Attacker venv (impacket and friends), inside WorkspaceRoot
# ---------------------------------------------------------------------------
if (-not $SkipVenv) {
    Write-Step "Creating attacker venv at $AttackerVenv"

    if (-not (Test-Path $AttackerVenv)) {
        & python -m venv $AttackerVenv
        if ($LASTEXITCODE -ne 0) { Fail "venv creation failed at $AttackerVenv." }
        Write-Ok "Venv created at $AttackerVenv"
    } else {
        Write-Warn "Venv already exists at $AttackerVenv -- reusing"
    }

    $attackerPip = "$AttackerVenv\Scripts\pip.exe"
    & $attackerPip install --quiet impacket
    if ($LASTEXITCODE -ne 0) { Fail "impacket install failed." }
    Write-Ok "impacket installed in $AttackerVenv"
}

# ---------------------------------------------------------------------------
# 4c. Sysinternals Suite, staged under WorkspaceRoot
# ---------------------------------------------------------------------------
if ($SkipSysinternals) {
    Write-Step "Skipping Sysinternals download (-SkipSysinternals)"
} else {
    Write-Step "Staging Sysinternals Suite at $SysinternalsDir"

    # PsExec.exe is a stable sentinel for "suite already extracted here"
    $sysinternalsSentinel = Join-Path $SysinternalsDir "PsExec.exe"
    if (Test-Path $sysinternalsSentinel) {
        Write-Warn "$SysinternalsDir already populated -- skipping download"
    } else {
        if (-not (Test-Path $SysinternalsDir)) {
            New-Item -ItemType Directory -Path $SysinternalsDir -Force | Out-Null
        }
        $zipPath = Join-Path $env:TEMP "SysinternalsSuite.zip"
        try {
            $oldProgress = $ProgressPreference
            $ProgressPreference = 'SilentlyContinue'   # Invoke-WebRequest is much faster without progress UI
            Invoke-WebRequest -Uri $SysinternalsUrl -OutFile $zipPath -UseBasicParsing
            $ProgressPreference = $oldProgress
            Write-Ok "Downloaded $SysinternalsUrl"
            Expand-Archive -LiteralPath $zipPath -DestinationPath $SysinternalsDir -Force
            Write-Ok "Extracted to $SysinternalsDir"
        } catch {
            Write-Warn "Sysinternals download/extract failed: $_"
            Write-Warn "Re-run with -SkipSysinternals to skip, or fetch the suite manually from:"
            Write-Warn "  https://learn.microsoft.com/en-us/sysinternals/downloads/"
        } finally {
            if (Test-Path $zipPath) { Remove-Item $zipPath -Force -ErrorAction SilentlyContinue }
        }
    }
}

# ---------------------------------------------------------------------------
# 5. Pull pyghidra-mcp Docker image
# ---------------------------------------------------------------------------
Write-Step "Pulling pyghidra-mcp Docker image"

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
        & $dockerExe pull ghcr.io/clearbluejar/pyghidra-mcp
        if ($LASTEXITCODE -ne 0) { Write-Warn "docker pull failed -- image will be fetched on first run" }
        else { Write-Ok "ghcr.io/clearbluejar/pyghidra-mcp pulled" }
    } else {
        Write-Warn "Docker daemon not running -- skipping pull; start Docker Desktop and re-run, or the image will be fetched on first use"
    }
} else {
    Write-Warn "docker not found -- skipping pull; install Docker Desktop"
}

# ---------------------------------------------------------------------------
# 6. Write pocsmith.yaml
# ---------------------------------------------------------------------------
Write-Step "Writing config template"

$exampleConfig = "$RepoRoot\pocsmith.yaml"

# Detect vcvarsall path and Ghidra regardless of whether the example config
# already exists -- both values are also referenced in the Next Steps output.
$vcPaths = @(
    "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat",
    "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvarsall.bat",
    "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsall.bat"
)
$vcFound = $vcPaths | Where-Object { Test-Path $_ } | Select-Object -First 1
$vcLine = if ($vcFound) { $vcFound } else { "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Auxiliary\\Build\\vcvarsall.bat" }

$ghidraDir = $env:GHIDRA_INSTALL_DIR
if (-not $ghidraDir) {
    $ghidraCommon = @("C:\Tools\ghidra_11.3", "C:\Tools\Ghidra")
    $ghidraDir = $ghidraCommon | Where-Object { Test-Path "$_\ghidraRun.bat" } | Select-Object -First 1
}
if (-not $ghidraDir) { $ghidraDir = "C:\\Tools\\ghidra_11.3" }

if (Test-Path $exampleConfig) {
    Write-Warn "$exampleConfig already exists -- not overwriting"
} else {

    $yaml = @"
vm:
  backend: hyperv
  vm_root: C:\VMs\pocsmith
  default_profile: win11-26h1-target
  # Invoked as `python -m <mcp_module>` from the pocsmith venv. The hyperv-mcp
  # package is installed editable from $HypervMcpRoot during setup.
  mcp_module: hyperv_mcp
  isos: []
  # isos:
  #   - path: C:\ISOs\Win11_26H1_x64.iso
  #     os_build: "28000"
  #     profile_name: win11-26h1-target

kd:
  # Invoked as `python -m <module>` from the pocsmith venv. The kd-mcp package
  # is installed editable from $KdMcpRoot during setup.
  module: kd_mcp

hyperv_guest:
  username_env: "HYPERV_GUEST_USERNAME"
  password_env: "HYPERV_GUEST_PASSWORD"
  victim_username_env: "HYPERV_GUEST_VICTIM_USERNAME"
  victim_password_env: "HYPERV_GUEST_VICTIM_PASSWORD"

ghidra:
  mode: docker
  image: "ghcr.io/clearbluejar/pyghidra-mcp"
  port: 8000
  extra_args: []
# ghidra (local fallback):
#   mode: local
#   pyghidra_mcp_cmd: pyghidra-mcp
#   ghidra_install_dir: C:\Tools\ghidra_11.3

compile:
  vcvarsall: '$vcLine'
  arch: x64

attacker_py:
  venv: $AttackerVenv
  sysinternals_dir: $SysinternalsDir
  packages:
    - impacket

llm:
  model: claude-opus-4-7
  api_key_env: "ANTHROPIC_API_KEY"
  context_threshold_pct: 70

ceilings:
  level_a: { wall_min: 60,  iterations: 40, dollars: 10.0,  phases: 8  }
  level_b: { wall_min: 240, iterations: 80, dollars: 50.0,  phases: 16 }
  level_c: { wall_min: 240, iterations: 80, dollars: 50.0,  phases: 16 }

paths:
  patchwatch_bin: C:\Tools\patchwatch\patchwatch.exe
  workspace_root: $WorkspaceRoot
"@
    Set-Content -Path $exampleConfig -Value $yaml -Encoding UTF8
    Write-Ok "Written to $exampleConfig"
}

# ---------------------------------------------------------------------------
# 7. Run prereq check to show full status
# ---------------------------------------------------------------------------
Write-Step "Running full prerequisite check"
& "$PSScriptRoot\check-prereqs.ps1" -VenvPath $PocsmithVenv -Config $exampleConfig

# ---------------------------------------------------------------------------
# 8. Next steps
# ---------------------------------------------------------------------------
Write-Host @"

=== Setup complete. Manual steps remaining: ===

  1. Activate the pocsmith venv (do this in every terminal before running pocsmith):
       $PocsmithVenv\Scripts\Activate.ps1

     Or invoke pocsmith directly without activating:
       $PocsmithVenv\Scripts\pocsmith.exe run --cve CVE-2026-XXXXX ...

  2. Edit config (optinal):
       notepad pocsmith.yaml

  3. Create a .env file (copy from .env.example) and fill in your credentials:
       copy .env.example .env
       notepad .env
       # Required: ANTHROPIC_API_KEY, HYPERV_GUEST_USERNAME, HYPERV_GUEST_PASSWORD
       # Optional: HYPERV_GUEST_VICTIM_USERNAME, HYPERV_GUEST_VICTIM_PASSWORD
       # Also set in your profile if needed: GHIDRA_INSTALL_DIR=$ghidraDir

  4. Create a Windows VM golden image:
       - Install Windows (ISO matching your target CVE's OS build)
       - Create a local account (username in HYPERV_GUEST_USERNAME)
       - Enable kernel debugging (use hyperv_configure_kdnet or hyperv_configure_kdcom)
       - Take a Hyper-V snapshot named 'clean'
       - Register the profile path in pocsmith.yaml under vm.vm_root

  5. Export a CVE from patchwatch and run:
       patchwatch export-poc-context CVE-2026-XXXXX --out C:\Research\pocsmith-workspaces
       pocsmith run --cve CVE-2026-XXXXX --config pocsmith.yaml

"@ -ForegroundColor White
