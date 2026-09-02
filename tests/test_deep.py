"""Deep injection tool tests: gating + clean runs against the fixture server
(which is not vulnerable, so they must finish with no findings)."""
from __future__ import annotations

import pytest

from webscan.tools.base import ToolOptions, get_tool, load_tools

DEEP = ["ssti", "cmdi", "lfi", "storedxss"]


@pytest.fixture(autouse=True)
def _tools():
    load_tools()


@pytest.mark.parametrize("tool_id", DEEP)
def test_deep_tool_requires_authorization(tool_id):
    report = get_tool(tool_id).func("http://127.0.0.1:9/", ToolOptions(authorized=False))
    assert report.status == "Blocked"


@pytest.mark.parametrize("tool_id", ["ssti", "lfi", "storedxss"])
def test_deep_tool_runs_clean_on_safe_target(tool_id, server):
    report = get_tool(tool_id).func(server, ToolOptions(authorized=True, timeout=5, max_items=4))
    assert report.status == "Finished"
    assert report.findings == []          # fixture server is not vulnerable


def test_all_deep_tools_registered():
    ids = {"ssti", "cmdi", "lfi", "storedxss"}
    assert ids <= {get_tool(i).id for i in ids if get_tool(i)}
