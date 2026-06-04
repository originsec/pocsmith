# pocsmith

An autonomous Windows POC developer. Reads [patchwatch](https://github.com/originsec/patchwatch) per-CVE reports and drives a Claude agent through writing, building, deploying, running, and verifying a Proof-of-Concept against a pre-patch Windows VM under a remote kernel debugger.

pocsmith wires a handful of MCP servers and an LLM into one workflow:

- **[patchwatch](https://github.com/originsec/patchwatch)** — produces the per-CVE reports (description, ranked binaries, ghidriff output) that pocsmith consumes.
- **[hyperv-mcp](https://github.com/originsec/hyperv-mcp)** — Hyper-V VM lifecycle: snapshots, KD configuration, PowerShell-Direct guest exec.
- **[kd-mcp](https://github.com/originsec/kd-mcp)** — remote kernel debugger wrapper (breakpoints, register/memory inspection, `!analyze -v`).
- **[pyghidra-mcp](https://github.com/clearbluejar/pyghidra-mcp)** — Ghidra running over the pre-patch binary with PDB symbols applied.
- **pocsmith-mcp** — driver tools the agent uses to compile, record attempts, declare success, and end phases. Implemented in this repo.
- **Anthropic-compatible LLM provider** — the agent that drives the loop. Anthropic is the default; Abliteration AI is supported via its Anthropic-compatible endpoint.

It is designed to run **locally** against your own infrastructure: your Hyper-V host, your VMs, your ISOs. The only outbound traffic is to the LLM endpoint you configure.

## Safety

pocsmith generates and runs exploit code. The system prompt restricts execution to the target Hyper-V VM via `hyperv-mcp`; payloads never run on the host. Treat any artifacts produced (POC sources, repro scripts) as authorized-research output and handle them accordingly. Only use against systems you control or are explicitly authorized to test.

## Prerequisites

### Hardware

- Windows 11 host with Hyper-V enabled (32 GB RAM recommended).
- At least one Windows ISO matching the CVE's patch KB (e.g. a 24H2 build).

### Software

| Dependency | Where to get it | Notes |
|---|---|---|
| Python 3.12+ | <https://python.org> | Must be on `PATH`. |
| Visual Studio 2022 | <https://visualstudio.com> | Install the *Desktop Development with C++* workload. |
| Windows SDK (Debugging Tools) | <https://developer.microsoft.com/windows/downloads/windows-sdk> | Needed for `kd.exe`. |
| Docker Desktop | <https://docker.com> | For `ghidra.mode: docker` (recommended). |
| Java 21+ | <https://adoptium.net> | Only for `ghidra.mode: local`. |
| Ghidra 11.x | <https://github.com/NationalSecurityAgency/ghidra> | Only for `ghidra.mode: local`; set `GHIDRA_INSTALL_DIR`. |
| pyghidra-mcp | `pip install pyghidra-mcp` | Only for `ghidra.mode: local`. |
| patchwatch | <https://github.com/originsec/patchwatch> | Produces the CVE reports pocsmith consumes. |
| hyperv-mcp | <https://github.com/originsec/hyperv-mcp> | Installed editable by `setup.ps1`; invoked as `python -m hyperv_mcp`. |
| kd-mcp | <https://github.com/originsec/kd-mcp> | Installed editable by `setup.ps1`; invoked as `python -m kd_mcp`. |

### Environment variables

Set these in a `.env` file at the workspace root (copy `.env.example` to start):

```
ANTHROPIC_API_KEY               your Anthropic API key
ABLITERATION_API_KEY            optional: your Abliteration AI key for llm.provider=abliteration-ai
HYPERV_GUEST_USERNAME           guest VM admin username (e.g. Administrator)
HYPERV_GUEST_PASSWORD           guest VM admin password
HYPERV_GUEST_VICTIM_USERNAME    optional: unprivileged account for EoP scenarios
HYPERV_GUEST_VICTIM_PASSWORD    optional: password for the victim account
GHIDRA_INSTALL_DIR              e.g. C:\Tools\ghidra_11.3  (only for ghidra.mode=local)
```

## Quickstart

```powershell
# 1. Clone and enter the project
git clone https://github.com/originsec/pocsmith.git
cd pocsmith

# 2. Run the setup script. Creates a venv, installs deps, generates a config
#    template, and pulls the pyghidra-mcp Docker image.
.\scripts\setup.ps1

# 3. Activate the venv
.\.venv\Scripts\Activate.ps1

# 4. Copy and edit the env file
copy .env.example .env
notepad .env

# 5. Copy and edit the config file
copy pocsmith.example.yaml pocsmith.yaml
notepad pocsmith.yaml

# 6. Export a CVE from patchwatch
patchwatch export-poc-context CVE-2026-XXXXX --out C:\Research\pocsmith-workspaces

# 7. Run pocsmith
pocsmith run --cve CVE-2026-XXXXX --config pocsmith.yaml
```

To check prerequisites without installing anything:

```powershell
.\scripts\check-prereqs.ps1
```

## CLI

```powershell
# Start a fresh run on an exported CVE
pocsmith run --cve CVE-2026-XXXXX --config pocsmith.yaml

# Steer the agent with a hint injected into the first phase kickoff
pocsmith run --cve CVE-2026-XXXXX --config pocsmith.yaml `
    --hint "The bug is in the pool allocation path; try heap spray with large IRPs first."

# Resume an interrupted run (re-uses notes.md and attempt history)
pocsmith resume --cve CVE-2026-XXXXX --config pocsmith.yaml

# List CVE workspaces under the configured workspace root
pocsmith inspect --workspace-root C:\Research\pocsmith-workspaces

# Regenerate the report.md for a workspace that already reached a success status
pocsmith report --cve CVE-2026-XXXXX --config pocsmith.yaml

# Live-tail the active session transcript in human-readable form
pocsmith tail --cve CVE-2026-XXXXX --config pocsmith.yaml --tail
# ...or point it at any session.jsonl directly:
pocsmith tail --file C:\Research\pocsmith-workspaces\CVE-2026-XXXXX\session.jsonl --thinking
```

Optional flags on `run` and `resume`:

| Flag | Default | Description |
|---|---|---|
| `--level A/B/C` | A | A = crash repro, B = controlled primitive, C = full exploit. |
| `--config` | — | Path to `pocsmith.yaml`. |
| `--workspace-root` | from config | Override workspace root. |
| `--vm-name` | from config | Hyper-V VM name. |
| `--hint TEXT` | _(none)_ | Hints injected into the agent's first kickoff message. |
| `--model` | from config, or `claude-opus-4-7` | Model id. Overrides `llm.model`. |
| `--skip-build-check` | off | Skip verifying that the VM's build matches `context.json`'s `patched_build`. |

## Configuration

`pocsmith.example.yaml` is the canonical example. The fields most worth knowing about:

```yaml
vm:
  backend: hyperv                          # only supported backend
  vm_root: C:\VMs\pocsmith                 # where Hyper-V VHDXs live
  default_profile: win11-24h2              # VM used when no --vm-name given
  mcp_module: hyperv_mcp                   # python -m hyperv_mcp (installed in venv)

kd:
  module: kd_mcp                           # python -m kd_mcp (installed in venv)

hyperv_guest:
  username_env: HYPERV_GUEST_USERNAME      # env var holding the admin username
  password_env: HYPERV_GUEST_PASSWORD
  victim_username_env: HYPERV_GUEST_VICTIM_USERNAME   # optional unprivileged account
  victim_password_env: HYPERV_GUEST_VICTIM_PASSWORD

ghidra:
  mode: docker                              # docker | local
  image: ghcr.io/clearbluejar/pyghidra-mcp
  port: 8000

compile:
  vcvarsall: C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat
  arch: x64

attacker_py:
  venv: C:\Research\pocsmith-workspaces\attacker-venv
  sysinternals_dir: C:\Research\pocsmith-workspaces\sysinternals   # optional
  packages: [impacket]

llm:
  provider: anthropic
  model: claude-opus-4-7
  api_key_env: ANTHROPIC_API_KEY
  context_threshold_pct: 70

ceilings:
  level_a: { wall_min: 60,  iterations: 40, dollars: 10.0, phases: 8  }
  level_b: { wall_min: 240, iterations: 80, dollars: 50.0, phases: 16 }
  level_c: { wall_min: 240, iterations: 80, dollars: 50.0, phases: 16 }

paths:
  patchwatch_bin: C:\Tools\patchwatch\patchwatch.exe
  workspace_root: C:\Research\pocsmith-workspaces
```

### Abliteration AI

To run through Abliteration AI's Anthropic-compatible endpoint, set `ABLITERATION_API_KEY` and use:

```yaml
llm:
  provider: abliteration-ai
  model: abliterated-model
  api_key_env: ABLITERATION_API_KEY
  context_threshold_pct: 70
```

`base_url` is optional and defaults to `https://api.abliteration.ai`.

### Local Ghidra (no Docker)

```yaml
ghidra:
  mode: local
  pyghidra_mcp_cmd: pyghidra-mcp
  ghidra_install_dir: C:\Tools\ghidra_11.3
```

## How it works

```
patchwatch report  -->  pocsmith run  -->  Claude agent (Agent SDK)
                                                |
                     +--------------------------+--------------------------+
                     v                          v                          v
                 hyperv-mcp                 kd-mcp                   pyghidra-mcp
              (VM lifecycle,           (kernel debugger)          (pre-patch binary
               guest exec,                                          + PDB analysis)
               KD setup)
                     |                          |
                     +----------+---------------+
                                |
                         pocsmith-mcp
                   (compile_c, attacker_py,
                    record_attempt, end_phase,
                    report_outcome, cve_context)
                                |
                         pre-patch VM
                         (kernel-debugged)
```

Each run is a sequence of *phases*, each one a bounded Claude Agent SDK session.
The agent iterates: edit POC source, compile, deploy to VM, trigger the bug,
capture KD output, record the attempt, revert, repeat. On `report_outcome`,
pocsmith replays the attempt on a fresh revert to verify the signal before
promoting artifacts.

### Phases

A *phase* is a coherent stretch of work — typically 3–6 iterations chasing one
hypothesis. A run is 3–8 phases. A phase ends when the agent calls `end_phase`
(voluntary, on changing hypothesis or hitting a wall) or when the driver's
input-token threshold (default 70% of the model's context window) is reached.

On phase end the full transcript is flushed to `transcripts/phase-N.jsonl`, the
session closes, and the next phase starts fresh — reading `notes.md` and a
compact summary of `attempts/*/status.json` instead of a transcript replay.

### Replay verification

`report_outcome` is the terminal call. On a success status, pocsmith:

1. Reverts the VM to a clean snapshot.
2. Re-attaches kd, re-deploys the recorded POC artifact, re-runs the recorded invocation.
3. Evaluates the agent-declared signal against the replay's kd output.

Signals are one of five typed kinds: `bugcheck`, `usermode_exception`,
`kd_breakpoint_hit`, `service_crash`, `assertion`. Anything outside this set is
recorded as `unverified_claim` and not promoted to an artifact.

The `register_predicate` DSL on `kd_breakpoint_hit` signals supports register
reads, dereferences with displacement, integer comparisons, and AND/OR.

### Budgets

| Level | Wall-clock | Iterations | Dollars | Phases |
|---|---|---|---|---|
| A | 60 min | 40 | $10 | 8 |
| B | 4 h | 80 | $50 | 16 |
| C | 4 h | 80 | $50 | 16 |

At 75% of any ceiling pocsmith injects a one-line reminder before the next
iteration. At 100% it forces the agent to call `report_outcome` and refuses
further tool calls.

## Workspace layout

`paths.workspace_root` is the root for all pocsmith runtime data: the shared
attacker venv, the Sysinternals tools cache, and one isolated subdirectory per
CVE.

```
<workspace-root>\
  attacker-venv\               shared Python venv with impacket etc. (setup.ps1)
  sysinternals\                Sysinternals Suite, host-side stage (setup.ps1)
  CVE-XXXX-NNNNN\
    context.json               static CVE context from patchwatch
    pre-patch\                 pre-patch binaries (hardlinked from patchwatch cache)
    post-patch\                post-patch binaries
    ghidriff\                  ghidriff diff outputs
    symbols\                   _NT_SYMBOL_PATH cache
    ghidra-project\            pyghidra .gpr (cached by pre-patch SHA)
    poc\                       agent's POC sources and builds
    notes.md                   agent exobrain - survives phase boundaries
    attempts\NNN\              per-iteration: status.json, kd.log, target.log
    transcripts\phase-N.jsonl  full session transcript per phase
    artifacts\                 written on verified success:
      poc\                     the verified POC
      repro.md                 reproduction steps
      verification.json        signal match record
      summary.md               run summary
      report.md                LLM-written narrative report
    .mcp.json                  auto-generated MCP server config
    pocsmith-run.lock          prevents concurrent runs on this workspace
```

The agent receives `POCSMITH_SYSINTERNALS` as an env var on the pocsmith MCP
when `attacker_py.sysinternals_dir` is set, and is instructed to deploy those
binaries into the guest via `hyperv_guest_put` rather than executing them on
the host.

## Architecture notes

- **Phase-scoped sessions**: each phase is a fresh Agent SDK session. Persistent state lives in `notes.md` (agent-curated) and `attempts/*/status.json` (driver-written). Transcripts are flushed to disk but not replayed.
- **Subagents for expensive reads**: the system prompt directs the agent to route large-token reads (full decompilations, kd dumps, ghidriff JSON) through `Task` subagents that return short structured summaries — the single biggest token-cost lever for Ghidra-heavy CVEs.
- **VM-only exploit execution**: the system prompt forbids running exploit code on the host. attacker_py is for network-side tooling (e.g. impacket) targeting the VM, not host-side exploitation.
- **Idempotent resume**: `pocsmith resume` re-uses the existing workspace, `notes.md`, and attempt history. It starts a new phase, not a full transcript replay.
- **Driver-managed MCP supervision**: `.mcp.json` is generated per workspace; kd-mcp and pyghidra-mcp are crash-restarted; hyperv-mcp failures abort the run.

See [docs/design.md](docs/design.md) for the complete design spec, including signal-predicate types, context-window management, and MCP server contracts.

## Testing

```powershell
# Unit tests (no VM, no Anthropic, no Ghidra)
pytest

# Live smoke tests are gated by RUN_LIVE=1
$env:RUN_LIVE = "1"; pytest -k smoke
```

## Contributing

Issues and PRs welcome. This is a research tool, not a product — expect rough edges and breaking changes between versions.

---

## License

Apache 2.0 — see [LICENSE](./LICENSE) and [NOTICE](./NOTICE)

Built by [Origin](https://originhq.com) for security research and red team operations.
