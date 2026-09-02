"""Optional adapters that enrich the suite with external tools when present.

Each adapter detects its binary at runtime (shutil.which). If the tool is not
installed the adapter degrades gracefully with install guidance instead of
failing - the native engine remains the always-available baseline. External
findings are normalised into the same Finding/ToolReport model so they render,
score and map to OWASP alongside native results.
"""
