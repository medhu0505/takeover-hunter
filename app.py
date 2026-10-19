"""Compatibility entrypoint for Takeover Hunter v2.0.0."""
import os
import sys
from takeover_hunter import create_app

app = create_app()

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else int(os.environ.get("PORT", 3000))
    app.run(host=os.environ.get("HOST", "0.0.0.0"), port=port, threaded=True)
