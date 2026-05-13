"""Pre-flight checks run before a POC session starts."""
import json
import os
import subprocess


def _parse_build(build_str: str) -> tuple[int, int]:
    """
    Parse a Windows build string into (build, ubr).

    Accepts "BBBBB.UBR", "10.0.BBBBB.UBR", or bare "BBBBB" (UBR=0).
    """
    parts = build_str.strip().split(".")
    if len(parts) == 4:
        return int(parts[2]), int(parts[3])
    if len(parts) == 2:
        return int(parts[0]), int(parts[1])
    if len(parts) == 1:
        return int(parts[0]), 0
    raise ValueError(f"Unrecognised build string format: {build_str!r}")


def _ps_escape(s: str) -> str:
    return s.replace("'", "''")


def _query_vm_build(vm_name: str, user: str, password: str) -> tuple[int, int]:
    """Return (build, ubr) from the registry of a running Hyper-V guest."""
    script = f"""
$cred = [System.Management.Automation.PSCredential]::new('{_ps_escape(user)}', [System.Net.NetworkCredential]::new('', '{_ps_escape(password)}').SecurePassword)
$r = Invoke-Command -VMName '{_ps_escape(vm_name)}' -Credential $cred -ErrorAction Stop -ScriptBlock {{
    $cv = Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion' -ErrorAction Stop
    [PSCustomObject]@{{ build=[int]$cv.CurrentBuildNumber; ubr=[int]$cv.UBR }}
}}
$r | ConvertTo-Json -Compress
"""
    proc = subprocess.run(
        ["powershell", "-NonInteractive", "-NoProfile", "-Command", script.strip()],
        capture_output=True, text=True, timeout=60,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"Failed to query build from VM '{vm_name}': "
            f"{(proc.stderr or proc.stdout).strip()}"
        )
    data = json.loads(proc.stdout.strip())
    return int(data["build"]), int(data["ubr"])


def check_vm_build(vm_name: str, patched_build: str,
                   user: str = "", password: str = "") -> None:
    """
    Verify the target VM's OS build is strictly below patched_build.

    Raises RuntimeError if the VM is at or above the patched build, or if
    guest credentials are not provided.
    """
    user = user or os.environ.get("HYPERV_GUEST_USERNAME", "")
    password = password or os.environ.get("HYPERV_GUEST_PASSWORD", "")
    if not user or not password:
        raise RuntimeError(
            "Hyper-V guest credentials are required for the VM build pre-flight check. "
            "Set HYPERV_GUEST_USERNAME and HYPERV_GUEST_PASSWORD in .env or as environment variables."
        )

    vm_build, vm_ubr = _query_vm_build(vm_name, user, password)
    fixed_build, fixed_ubr = _parse_build(patched_build)

    vm_tuple = (vm_build, vm_ubr)
    fixed_tuple = (fixed_build, fixed_ubr)

    if vm_tuple >= fixed_tuple:
        raise RuntimeError(
            f"VM '{vm_name}' build {vm_build}.{vm_ubr} is >= patched build "
            f"{fixed_build}.{fixed_ubr}. "
            f"Revert to a pre-patch snapshot before running pocsmith."
        )
