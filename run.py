"""
run.py — project root launcher
================================
Run this file from anywhere to start the WDAC Analyzer:

    python run.py                    # analyse existing logs/
    python run.py --collect          # pull from PCs then analyse
    python run.py --collect --pcs 1-10
    python run.py --help

This file just delegates to core/main.py.
"""

from core.main import main

if __name__ == "__main__":
    main()
