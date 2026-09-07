"""Print "true"/"false" for the diff's `empty` flag, for use as an Action output."""
import json
import sys

print(str(bool(json.load(open(sys.argv[1])).get("empty", False))).lower())
