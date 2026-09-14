"""SSE framing tests."""
import json

from takeover_hunter.sse import sse_event


def test_sse_event_format():
    out = sse_event("progress", {"found": 3})
    assert out.startswith("event: progress\n")
    assert "data: " in out
    assert out.endswith("\n\n")
    payload = json.loads(out.split("data: ", 1)[1].strip())
    assert payload == {"found": 3}


def test_sse_event_serialises_nested():
    out = sse_event("done", {"vulnerable": [{"sub": "a.example.com"}], "count": 1})
    payload = json.loads(out.split("data: ", 1)[1].strip())
    assert payload["count"] == 1
    assert payload["vulnerable"][0]["sub"] == "a.example.com"
