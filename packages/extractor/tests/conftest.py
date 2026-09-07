import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PKG_ROOT = os.path.dirname(HERE)
if PKG_ROOT not in sys.path:
    sys.path.insert(0, PKG_ROOT)

FIXTURES = os.path.join(HERE, "fixtures")
SCHEMA_DIR = os.path.join(os.path.dirname(os.path.dirname(PKG_ROOT)), "schema")
