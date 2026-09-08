#!/usr/bin/env python3

"""Deprecated entry point.

This script previously contained a standalone, duplicated copy of the
detection pipeline. The duplicate logic has been removed; this wrapper
delegates to the canonical pipeline in siem_lab_v2.py so existing
invocations of ``python3 siem_lab.py`` keep working.
"""

from __future__ import annotations

import sys

from siem_lab_v2 import main as run_pipeline

if __name__ == "__main__":
    print(
        "siem_lab.py is deprecated; running the current pipeline "
        "(siem_lab_v2.py).\n"
    )
    sys.exit(run_pipeline())
