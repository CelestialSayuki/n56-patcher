"""Run independent per-library work in fork workers (they inherit open cache indexes)."""
import multiprocessing
import os

_job = None


def _run(item):
    return _job(item)


def map_libraries(function, items):
    global _job
    _job = function
    with multiprocessing.get_context('fork').Pool(os.cpu_count() or 1) as pool:
        return pool.map(_run, list(items), chunksize=1)
