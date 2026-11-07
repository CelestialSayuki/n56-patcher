"""统一彩色日志，沿用 master 脚本的 [*]/[!]/[ERROR] 风格。"""
import sys

_G, _Y, _R, _N = "\033[0;32m", "\033[1;33m", "\033[0;31m", "\033[0m"
_C = sys.stderr.isatty()


def _c(code, s):
    return f"{code}{s}{_N}" if _C else s


def log(msg):
    print(_c(_G, "[*]"), msg, file=sys.stderr, flush=True)


def warn(msg):
    print(_c(_Y, "[!]"), msg, file=sys.stderr, flush=True)


def step(n, total, msg):
    print(_c(_G, f"[{n}/{total}]"), msg, file=sys.stderr, flush=True)


def stage(name):
    """端到端进入子阶段；GUI 靠这一行更新节点，格式改动要同步 gui.py 的 SUB_LINE。"""
    print(f"[>] {name}", file=sys.stderr, flush=True)


class Die(SystemExit):
    """受控失败：带非零退出码，GUI/CLI 都能捕获。"""


def die(msg):
    print(_c(_R, "[ERROR]"), msg, file=sys.stderr, flush=True)
    err = Die(1)
    err.message = str(msg)  # 供离线校验等调用方读取原因
    raise err
