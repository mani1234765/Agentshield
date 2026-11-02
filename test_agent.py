from agent import run_agent
import pytest

def test_agent_blocks_manager_delete():
    result = run_agent("manager", "delete", approved=True)

    assert result["executed"] is False

def test_agent_allows_intern_read():
    result = run_agent("intern", "read")

    assert result["executed"] is True
    assert result["result"] == "Successfully read the file"

def test_agent_unknown_tool():
    result = run_agent("admin", "unknown")

    assert result["executed"] is False
