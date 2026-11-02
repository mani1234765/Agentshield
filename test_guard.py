from fastapi.testclient import TestClient
import pytest
from guard import execute_tool
from main import app

client = TestClient(app)
def test_allowed_tool_execute():
    calls = []

    def read_file():
        calls.append("executed")
        return "Confidential report contents"

    response = execute_tool(
        role= "intern",
        action= "read",
        approved= False,
        tool_function=read_file
    )
    assert response["executed"] is True
    assert response["result"] == "Confidential report contents"
    assert calls == ["executed"]


def test_blocked_tool_does_not_execute():
    calls = []

    def dangerous_tool():
        calls.append("executed")
        return "File Deleted"

    response = execute_tool(
        role= "manager",
        action= "delete",
        approved= True,
        tool_function=dangerous_tool
    )
    assert response["executed"] is False
    assert calls == []
