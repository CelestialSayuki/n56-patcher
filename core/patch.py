"""Patch 基类 + 注册表（A + feature 标签的核心）。

一个 patch = 一层里的一件事，一个文件。requires 补齐依赖，after 安排已选补丁的顺序。

layer  : ibec | kc | dt | rootfs   （iBSS/TrustCache 是目标级固定组件）
role   : base | transform | overlay | stream | finalize
  - base      : 提供某层的起始二进制（kc 的起始内核、dt 的起始设备树）。每层选且仅选一个。
  - transform : 在起始二进制上原地叠加的变换（kc 的 pmu/mt/chestnut…、dt 的功能补充）。顺序由 requires/after 决定。
  - stream    : rootfs 基底流式写入（唯一）。
  - overlay   : rootfs 的文件集 overlay（health/ui/蓝牙…），各自独立部署。
  - finalize  : rootfs 收尾（var→DataB、fsck 替换、SEP 固件、keybags、改 role）。
feature: core/touch/audio/wifi/baseband/sep/ui/bluetooth/health… 选挂的单位。
scope  : device（跨 iOS 版本复用）| version（随 iOS 版本变）。

apply() 签名随 role：
  base      : apply(ctx) -> 产出二进制路径
  transform : apply(ctx, art) -> 新二进制路径（art 为当前层产物）
  stream/overlay/finalize : apply(ctx) -> None（经 ctx.ssh 直接作用于设备）
"""
import importlib.util
import os

from . import log

LAYER_ORDER = ["ibec", "dt", "kc", "rootfs"]
ROLE_ORDER = {"base": 0, "transform": 1, "stream": 2, "overlay": 3, "finalize": 4}
_REGISTRY = []


class Patch:
    id = None
    layer = None
    feature = "core"
    scope = "version"
    role = "transform"
    requires = ()
    after = ()       # Order only: absent patches are not selected.
    donors = ()
    note = ""
    manual = False   # True: 需人工/多步部署，flow 默认跳过并打印权威路径，除非显式允许

    def __init_subclass__(cls, **kw):
        super().__init_subclass__(**kw)
        if cls.id:
            _REGISTRY.append(cls)

    def apply(self, ctx, art=None):
        raise NotImplementedError(f"{self.id} 未实现 apply")

    def prepare(self, ctx):
        """提前准备需要 DFU 的构建输入。"""
        pass

    def __repr__(self):
        return f"<{self.id} {self.layer}/{self.role} feat={self.feature}>"


def discover(patches_dir=None, *, version="ios13"):
    """加载共享补丁与目标系统的补丁。"""
    _REGISTRY.clear()
    patches_dir = patches_dir or os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "patches")
    for group in ("shared", version):
        for layer in LAYER_ORDER:
            ldir = os.path.join(patches_dir, group, layer)
            if not os.path.isdir(ldir):
                continue
            for fn in sorted(os.listdir(ldir)):
                if not fn.endswith(".py") or fn.startswith("_"):
                    continue
                path = os.path.join(ldir, fn)
                name = f"patches.{group}.{layer}.{fn[:-3]}"
                spec = importlib.util.spec_from_file_location(name, path)
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
    _REGISTRY.sort(key=lambda cls: (cls.layer, cls.__module__.rsplit(".", 1)[-1]))
    return list(_REGISTRY)


def _instances():
    return {c.id: c() for c in _REGISTRY}


def _topo(patches):
    """按 requires 和可选 after 做稳定拓扑排序（同层内）。"""
    by_id = {p.id: p for p in patches}
    out, seen, temp = [], set(), set()

    def visit(p):
        if p.id in seen:
            return
        if p.id in temp:
            log.die(f"patch 依赖成环: {p.id}")
        temp.add(p.id)
        for dep in (*p.requires, *p.after):
            if dep in by_id:
                visit(by_id[dep])
        temp.discard(p.id)
        seen.add(p.id)
        out.append(p)

    for p in patches:
        visit(p)
    return out


def select(target):
    """按目标清单挑选 patch，返回 {layer: [有序 patch 实例]}。

    选中规则：patch.feature ∈ target['features'] 或 patch.id ∈ target.get('patches')，
    kc_patches 可覆盖 KC transform 选择；exclude 排除补丁；bases 指定各层基底。
    """
    discover(version=target.get("version", "ios13"))
    inst = _instances()
    features = set(target.get("features", []))
    want_ids = set(target.get("patches", []))
    kc_picks = target.get("kc_patches")
    if kc_picks is not None:
        want_ids.update(kc_picks)
    exclude = set(target.get("exclude", []))
    bases = target.get("bases", {})

    unknown = (want_ids | exclude) - inst.keys()
    if unknown:
        log.die(f"未知 patch: {', '.join(sorted(unknown))}")
    if kc_picks is not None:
        invalid = [pid for pid in kc_picks if inst[pid].layer != "kc" or inst[pid].role == "base"]
        if invalid:
            log.die(f"--patches 请选择 KC transform: {', '.join(invalid)}")
    known_features = {p.feature for p in inst.values()}
    unknown_features = features - known_features
    if unknown_features:
        log.die(f"未知 feature: {', '.join(sorted(unknown_features))}")

    chosen = []
    for p in inst.values():
        if p.id in exclude:
            continue
        if p.role == "base":
            if bases.get(p.layer) == p.id:
                chosen.append(p)
            continue
        if p.layer == "kc" and kc_picks is not None:
            if p.id in kc_picks:
                chosen.append(p)
        elif p.feature in features or p.id in want_ids:
            chosen.append(p)

    # A selected transform brings its prerequisites with it. Explicit excludes
    # and a different base are configuration errors rather than partial builds.
    selected = {p.id for p in chosen}
    pending = list(chosen)
    while pending:
        patch = pending.pop()
        for dep in patch.requires:
            if dep in selected:
                continue
            if dep in exclude or dep not in inst:
                log.die(f"{patch.id} 需要 {dep}，请调整 patches/exclude")
            required = inst[dep]
            if required.role == "base" and bases.get(required.layer) != dep:
                log.die(f"{patch.id} 需要基底 {dep}")
            selected.add(dep)
            chosen.append(required)
            pending.append(required)

    # 校验每层 base 唯一
    result = {}
    for layer in LAYER_ORDER:
        group = [p for p in chosen if p.layer == layer]
        bases_in = [p for p in group if p.role == "base"]
        if layer in ("dt", "kc") and len(bases_in) != 1:
            names = [b.id for b in bases_in]
            log.die(f"{layer} 层需要且仅需要一个 base（当前: {names or '无'}；"
                    f"在清单 bases['{layer}'] 指定）")
        group.sort(key=lambda p: (ROLE_ORDER.get(p.role, 9),))
        group = _topo(group)
        group.sort(key=lambda p: ROLE_ORDER.get(p.role, 9))
        result[layer] = group
    return result


def summary(selection):
    lines = []
    for layer in LAYER_ORDER:
        for p in selection.get(layer, []):
            lines.append(f"  [{layer:6s}] {p.role:9s} {p.feature:9s} {p.id}")
    return "\n".join(lines)
