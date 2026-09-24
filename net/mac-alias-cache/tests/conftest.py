import os
import sys

SCRIPTS = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "opnsense", "scripts", "OPNsense", "MacAliasCache",
)
sys.path.insert(0, SCRIPTS)
