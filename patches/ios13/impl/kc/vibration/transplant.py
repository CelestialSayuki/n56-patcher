"""Build the iOS 13 DRV2604 driver with the shared transplant engine.

构建时由 patches/ios13/kc/vibration.py 在进程内调用 build()。
单独运行（仓库根目录）：
  python3 -m patches.ios13.impl.kc.vibration.transplant --input <13 内核> --out <输出目录> [--derived <目录>]
"""
import argparse
import json
from pathlib import Path
from core.context import DERIVED_DIR
from patches.shared.impl.kc.sn2400.macho import Kernel
from patches.shared.impl.kc.vibration import transplant as engine
from patches.ios13.impl.kc.vibration.profile import profile


def target_symbols(input_path, output_dir):
    """输入内核的符号表，写到输出目录供移植引擎读取。"""
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "target-symbols.json"
    path.write_text(json.dumps({name: hex(address)
                                for name, address in Kernel(input_path).symbols().items()}))
    return path


def build(input_path, output_dir, derived):
    """把 DRV2604 移植进 input_path，产物写到 output_dir，返回 kernelcache.vibration.raw 路径。"""
    input_path, output_dir = Path(input_path), Path(output_dir)
    engine.build(input_path, output_dir, profile(derived, target_symbols(input_path, output_dir)))
    return output_dir / "kernelcache.vibration.raw"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--input", type=Path, required=True, help="iOS 13 输入内核（raw）")
    parser.add_argument("--out", type=Path, required=True, help="输出目录")
    parser.add_argument("--derived", type=Path, default=Path(DERIVED_DIR),
                        help="从 IPSW 生成的输入目录，默认 ipsw/cache/derived")
    args = parser.parse_args(argv)
    build(args.input, args.out, args.derived)


if __name__ == "__main__":
    main()
