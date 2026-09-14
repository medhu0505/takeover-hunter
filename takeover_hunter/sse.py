"""Server-Sent Events (SSE) framing helpers."""
from __future__ import annotations

import json
from typing import Any


def sse_event(event: str, data: Any) -> str:
    """Serialise ``data`` as a single SSE frame for the named ``event``.

    Produces the ``event: <name>\\ndata: <json>\\n\\n`` wire format consumed by
    the browser ``EventSource`` API.
    """
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"
