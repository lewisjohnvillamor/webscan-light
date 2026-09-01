# Contributing

Thanks for helping improve webscan-light.

## Development setup

```bash
pip install -e ".[web,cli,dev]"
pytest                       # runs against a local fixture server, no network
python -m pyflakes webscan   # lint
```

## Adding a check or a tool

- A **website-scanner check** is a function decorated with
  `@check(test_id, description)` in `webscan/checks/`; the description is the
  line shown in the report's coverage list. Add the module to
  `webscan/checks/__init__.py`.
- A **suite tool** is a function decorated with `@tool(...)` in
  `webscan/tools/` returning a `ToolReport`. Add it to
  `webscan/tools/__init__.py` and a short code to `TOOL_GLYPHS` in
  `webscan/report/generic.py`.

## Guidelines

- Standard library first; the only runtime deps are `requests`,
  `beautifulsoup4` and `jinja2` (plus optional `rich` and the web extras).
- Every finding needs a clear risk description, recommendation and CWE/OWASP
  classification.
- Active/intrusive tools must be gated behind an authorisation flag.
- Add or update tests for anything you change; keep `pytest` green.
