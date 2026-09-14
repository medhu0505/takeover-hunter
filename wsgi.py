"""Production WSGI entrypoint.

Used by gunicorn/uWSGI: ``gunicorn wsgi:app``. Building the app here (rather
than at import time inside the package) keeps ``import takeover_hunter`` cheap
for tests and tooling.
"""
from takeover_hunter.app import create_app

app = create_app()

if __name__ == "__main__":
    config = app.config["TH_CONFIG"]
    app.run(host=config.host, port=config.port, debug=config.debug, threaded=True)
