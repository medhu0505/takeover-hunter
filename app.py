#!/usr/bin/env python3
"""Development entrypoint (compatibility shim).

The application now lives in the :mod:`takeover_hunter` package. This module
is kept so that ``python app.py`` still starts a local development server, and
so ``from app import app`` keeps working for any external tooling.

For production use gunicorn against :mod:`wsgi` instead:

    gunicorn --workers 4 --threads 8 --timeout 300 wsgi:app
"""
from takeover_hunter.app import create_app

app = create_app()

if __name__ == "__main__":
    config = app.config["TH_CONFIG"]
    print(f"[*] Takeover Hunter starting on http://{config.host}:{config.port}")
    app.run(host=config.host, port=config.port, debug=config.debug, threaded=True)
