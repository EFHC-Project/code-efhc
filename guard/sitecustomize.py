"""Application-level egress guard for Python checker subprocesses.

The intake process does not import this module. Checker subprocesses receive
/app/guard on PYTHONPATH so common socket connection paths fail closed.
"""
from __future__ import annotations

import os
import socket

if os.environ.get("CODE_EFHC_BLOCK_NETWORK") == "1":
    def _blocked(*args, **kwargs):
        raise PermissionError("network disabled for CODE EFHC checker subprocess")

    socket.create_connection = _blocked
    socket.socket.connect = _blocked
    socket.socket.connect_ex = _blocked
