"""Emit `verdict=` and `severity=` lines for use as Action outputs.

The PR comment leads with this one line so a reviewer knows whether to open the
visual diff before opening it -- a bare link makes them click to find out that
nothing changed.
"""
import json
import sys

d = json.load(open(sys.argv[1]))
findings = d.get("findings") or []
if d.get("empty") or not findings:
    print("severity=NONE")
    print("verdict=No permission changes. The permission graphs are semantically identical.")
else:
    top = findings[0]
    sev = str(top.get("severity", "info")).upper()
    print(f"severity={sev}")
    extra = ""
    n = len(findings)
    if n > 1:
        extra = f" (+{n - 1} more finding{'s' if n > 2 else ''})"
    print(f"verdict={top.get('title', 'permission changes detected')}{extra}")
