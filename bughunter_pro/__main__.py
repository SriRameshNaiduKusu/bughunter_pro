"""
Allow running as: python -m bughunter_pro [args]
This is what the wrapper scripts call.
"""

import sys
import os

# Ensure the project root is in the Python path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from bughunter_pro.main import main

if __name__ == "__main__":
    main()