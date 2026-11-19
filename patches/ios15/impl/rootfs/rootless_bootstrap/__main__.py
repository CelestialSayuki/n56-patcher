"""Fill ipsw/cache/ios15-rootless with the pinned rootless/rootful downloads.

Network input preparation only (like patches/ios15/inputs.py for the IPSWs);
every file is checked against its fixed SHA-256. The build itself is offline.
"""
from . import artifacts


if __name__ == '__main__':
    artifacts.fetch()
    print(f'pinned downloads present in {artifacts.DOWNLOADS}')
