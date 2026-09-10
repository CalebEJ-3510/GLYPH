"""
pytest conftest — adds the project root to sys.path so that
``import src.xxx`` works from any test file without installing the package.
"""
import sys
from pathlib import Path

# Insert the project root (directory containing src/) at the front of sys.path
sys.path.insert(0, str(Path(__file__).parent))