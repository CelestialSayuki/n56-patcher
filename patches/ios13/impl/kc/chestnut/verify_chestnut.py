#!/usr/bin/env python3
"""Verify the saved Chestnut candidate using the shared independent decoder."""
import argparse
from pathlib import Path
from transplant import verify_candidate

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build_dir', type=Path, nargs='?', default=Path(__file__).resolve().parent / 'build')
    verify_candidate(parser.parse_args().build_dir)
