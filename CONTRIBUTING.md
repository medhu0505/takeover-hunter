# Contributing / Development guide

> This is proprietary software (see `LICENSE`). This guide documents the
> development workflow for the maintainer and any authorized contributor under
> a written agreement.

## Setup

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements-dev.txt
```

## Running

```bash
python app.py                 # dev server (Flask), http://127.0.0.1:5000
gunicorn wsgi:app             # production-style
```

## Tests & lint

```bash
python -m pytest                       # run the suite
python -m pytest --cov=takeover_hunter  # with coverage
python -m pyflakes takeover_hunter tests wsgi.py app.py
```

CI (`.github/workflows/ci.yml`) runs lint + tests on Python 3.10–3.13 and a
Docker build on every push and pull request. Keep it green.

## Conventions

- **The validation boundary is sacred.** Any new value that comes from a
  request and later reaches DNS, HTTP, or a subprocess MUST pass through
  `takeover_hunter/validation.py` first. Add a test to `test_validation.py`
  for any new input.
- **Never use `shell=True`.** Invoke external tools with argument lists via
  `recon._run_argv`. Re-validate tool output with `recon._hosts_in_scope`.
- **Keep modules single-purpose.** New concerns get a new module, not a dump
  into `app.py`.
- **Config over constants.** New tunables belong in `config.py` and
  `.env.example`, read from the environment.
- **Test the logic, mock the network.** DNS/HTTP are mocked in tests; no test
  should make a real outbound request.

## Adding a provider fingerprint

Add an entry to `FINGERPRINTS` in `takeover_hunter/fingerprints.py` with a
unique `patterns` list. `test_fingerprints.py::test_no_duplicate_patterns_...`
enforces pattern uniqueness; add a positive match case while you are there.

## Adding an endpoint

1. Add the worker logic to `ReconEngine` (streaming) or a pure helper.
2. Wire the route in `app.create_app`, validating all input up front.
3. For streaming routes, reuse `_stream` with a terminal spec.
4. Add route tests to `test_api.py` (happy path + validation rejection).
