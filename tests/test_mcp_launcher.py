import json
from pathlib import Path
from pocsmith.mcp_launcher import write_mcp_json, McpSpec


def test_writes_mcp_json(tmp_path: Path):
    specs = [
        McpSpec(name="hyperv", command="C:/x/hyperv-mcp.exe", args=[], env={}),
        McpSpec(name="kd", command="python", args=["C:/tools/kd-mcp/kd_mcp.py"], env={}),
        McpSpec(name="ghidra", command="pyghidra-mcp", args=["--project", "C:/p"],
                env={"GHIDRA_INSTALL_DIR": "C:/Tools/ghidra"}),
    ]
    out = tmp_path / ".mcp.json"
    write_mcp_json(out, specs)
    obj = json.loads(out.read_text())
    assert set(obj["mcpServers"].keys()) == {"hyperv", "kd", "ghidra"}
    assert obj["mcpServers"]["kd"]["args"] == ["C:/tools/kd-mcp/kd_mcp.py"]
    assert obj["mcpServers"]["ghidra"]["env"]["GHIDRA_INSTALL_DIR"] == "C:/Tools/ghidra"
