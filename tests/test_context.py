from pathlib import Path
import json
from pocsmith.context import CveContext, load_context


def test_loads_real_shape(tmp_path: Path):
    p = tmp_path / "context.json"
    p.write_text(json.dumps({
        "cve_id": "CVE-2026-23669",
        "cvss": 8.8,
        "kb": "KB5079466",
        "title": "RPC RCE",
        "description": "UAF in RPC runtime",
        "primary_binaries": ["rpcrt4.dll"],
        "deep_analysis": [{
            "binary": "rpcrt4.dll",
            "function": "FinishUsingContextHandle",
            "relevance": 0.95,
            "summary": "refcount UAF",
            "before_code": "old", "after_code": "new",
        }],
        "prepatch_paths": {"rpcrt4.dll": "pre-patch/abcd/rpcrt4.dll"},
        "postpatch_paths": {"rpcrt4.dll": "post-patch/3565/rpcrt4.dll"},
        "ghidriff_dir": "ghidriff/",
    }))
    ctx = load_context(p)
    assert ctx.cve_id == "CVE-2026-23669"
    assert ctx.cvss == 8.8
    assert ctx.deep_analysis[0].relevance == 0.95
    assert ctx.prepatch_paths["rpcrt4.dll"].endswith("rpcrt4.dll")
