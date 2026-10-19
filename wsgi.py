"""WSGI production entrypoint for Takeover Hunter v2.0.0."""
import os
from takeover_hunter import create_app

app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 3000))
    host = os.environ.get("HOST", "0.0.0.0")
    app.run(host=host, port=port, threaded=True)
