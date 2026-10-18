"""PyInstaller entry point for FabulousRemote.exe."""

import sys

from fabremote.app import main

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
