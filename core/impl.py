"""Run repository implementations with this build's firmware and output paths."""
import os
from pathlib import Path
import sys

from .context import REPO
from .tools import run


def run_impl(ctx, script, args=(), inp=None, output_dir=None):
    root = Path(REPO) / 'patches/impl'
    ctx.ensure_derived()
    env = os.environ.copy()
    env.update(N56_DONORS=ctx.source_root, N56_DERIVED=ctx.derived_root, N56_WORK=ctx.work)
    env['PYTHONPATH'] = os.pathsep.join(str(root / p) for p in
                                      ('', 'common', 'kc/sn2400', 'kc/vibration'))
    if inp is not None:
        env['N56_INPUT'] = str(inp)
    if output_dir is not None:
        env['N56_OUTPUT'] = str(output_dir)
    result = run([sys.executable, str(root / script), *map(str, args)], env=env)
    return result


def transform(ctx, script, inp, name, directory_args=False, extra=()):
    output_dir = ctx.wk(name)
    if directory_args:
        out = str(Path(output_dir) / ('kernelcache.' + name + '.raw'))
        args = ['--input', inp, '--out', output_dir, *extra]
    else:
        out = ctx.wk('kc.' + name + '.raw')
        args = [inp, out, *extra]
    run_impl(ctx, script, args, inp=inp, output_dir=output_dir)
    if not Path(out).is_file():
        raise FileNotFoundError(out)
    return out
