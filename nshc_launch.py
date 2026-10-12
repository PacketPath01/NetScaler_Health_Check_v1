"""One program for the window and the command line.

Double-click opens the window. Pass scan, decrypt, or import-checks to use the command line.
"""

from __future__ import annotations

import sys


def main() -> None:
    if len(sys.argv) > 1:
        _attach_cli_console()
        from nshc.cli import main as cli_main

        raise SystemExit(cli_main())
    from nshc.gui import main as gui_main

    gui_main()


def _attach_cli_console() -> None:
    """A windowed program has no console until it attaches to the terminal that launched it."""
    if sys.platform != "win32" or not getattr(sys, "frozen", False):
        return
    import ctypes

    kernel32 = ctypes.windll.kernel32
    kernel32.AttachConsole.argtypes = [ctypes.c_uint32]
    kernel32.AttachConsole.restype = ctypes.c_int
    if not kernel32.AttachConsole(0xFFFFFFFF):
        kernel32.AllocConsole()
    try:
        sys.stdout = open("CONOUT$", "w", encoding="utf-8", errors="replace", buffering=1)
        sys.stderr = open("CONOUT$", "w", encoding="utf-8", errors="replace", buffering=1)
        sys.stdin = open("CONIN$", "r", encoding="utf-8", errors="replace")
    except OSError:
        return


if __name__ == "__main__":
    main()
