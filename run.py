#!/usr/bin/env python3
"""
WipeVault launcher — run from project root.
    python run.py
"""
import sys
import os

# Ensure src/ is on the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from wipevault import main

if __name__ == "__main__":
    main()
