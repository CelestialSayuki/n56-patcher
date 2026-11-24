#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""n56-patcher 本地网页界面（标准库 http.server，零依赖）。

本机 Python 可能不带 tkinter，故用浏览器界面：选目标、勾 feature、切选项、点阶段，
日志实时回显。每个阶段以 subprocess 跑 n56patcher.py，输出流式送到页面。

运行：python3 gui.py            # 默认 http://127.0.0.1:8756
      python3 gui.py --port 9000
需要 root 的阶段（写 rootfs、安装、端到端、宗卷写操作）：本界面不是 root 时，页面会弹窗要管理员
密码，只用来经 sudo 启动那一个阶段，不保存。也可以直接 sudo python3 gui.py 启动，就不再弹窗。
宗卷设置是主页面里的弹窗（旧地址 /volumes 会跳转过来）。
仅监听本地回环，不对外。
"""
import sys
sys.dont_write_bytecode = True                  # 仓库里不留 __pycache__（子进程同样）
import os
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
import argparse
import json
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

REPO = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "tools", "bin", "pydeps"))

from core.context import load_target, TARGETS_DIR
from core import patch as patchmod
from core.jailbreak_mode import metadata as jailbreak_metadata, configure as configure_jailbreak_mode, require_backend

SUDO_STAGES = {"rootfs", "patch-rootfs", "build", "boot", "install", "all"}
# 会起 ramdisk（SSH + iproxy）的阶段：残留的 root iproxy 在时，要先问密码
RAMDISK_STAGES = {"ramdisk", "extract-im4m", "volumes"}
STAGES = ["init", "ramdisk", "extract-im4m", "volumes", "rootfs",
          "patch-rootfs", "build", "boot", "all", "status", "list"]


def list_targets():
    out = [fn[:-3].replace("_", "-") for fn in sorted(os.listdir(TARGETS_DIR))
           if fn.endswith(".py") and not fn.startswith("_")]
    return out or ["n56-ios13"]


# discover() 会清空并重填全局注册表；服务是多线程的，切换目标时两个请求并发会把两个版本的补丁混在一起
DISCOVER_LOCK = threading.Lock()


def target_features(name):
    try:
        t = load_target(name)
    except SystemExit:
        return [], []
    with DISCOVER_LOCK:
        classes = patchmod.discover(version=t.get("version", "ios13"))
    allf = sorted({c.feature for c in classes})
    return sorted(t.get("features", [])), allf


class Runner:
    """串行跑阶段，日志进内存缓冲，页面按 offset 拉取。"""
    def __init__(self):
        self.lines = []
        self.proc = None
        self.started = 0.0          # 本次阶段开始的 epoch 秒；供前端算用时（刷新也准）
        self.lock = threading.Lock()

    def running(self):
        return self.proc is not None and self.proc.poll() is None

    def put(self, s):
        with self.lock:
            self.lines.append(s)

    def since(self, off):
        with self.lock:
            return self.lines[off:], len(self.lines)

    def start(self, args, password=None, on_exit=None):
        """password：本界面不是 root 时，用 sudo -S 以管理员身份跑这一个阶段。密码只写进 sudo 的
        stdin 一次，不记录、不保留。sudo 的真实用户仍是本进程用户，stop() 照常能终止它。
        on_exit(returncode)：阶段结束后回调（如宗卷识别成功后解锁宗卷设置）。"""
        if self.running():
            self.put("[!] 有阶段正在运行。\n")
            return False
        self.started = time.time()
        self.put("\n$ " + ("sudo " if password else "") + " ".join(args) + "\n")
        threading.Thread(target=self._spawn, args=(args, password, on_exit), daemon=True).start()
        return True

    def _spawn(self, args, password=None, on_exit=None):
        command = ["sudo", "-S", "-p", "", "--", *args] if password else args
        try:
            self.proc = subprocess.Popen(command, cwd=REPO, stdout=subprocess.PIPE,
                                         stderr=subprocess.STDOUT, bufsize=1, text=True,
                                         stdin=subprocess.PIPE if password else subprocess.DEVNULL)
            if password:
                self.proc.stdin.write(password + "\n")
                self.proc.stdin.close()
        except Exception as e:
            self.put(f"[ERROR] 启动失败：{e}\n")
            return
        for line in self.proc.stdout:
            self.put(line)
        self.proc.wait()
        if on_exit:
            try:
                on_exit(self.proc.returncode)
            except Exception as e:
                self.put(f"[!] 阶段收尾回调失败：{e}\n")
        self.put(f"[*] 阶段结束，退出码 {self.proc.returncode}\n")

    def stop(self):
        if self.running():
            self.proc.terminate()
            self.put("[!] 已请求停止。\n")


RUNNER = Runner()


def need_root():
    return os.geteuid() != 0


def stale_root_proxies():
    """之前 sudo 跑留下的本项目 iproxy（属于 root）。普通用户结束不了，要先在网页上输入密码。"""
    iproxy = os.path.join(REPO, "tools/SSHRD_Script/Darwin/iproxy")
    out = subprocess.run(["ps", "-axo", "pid=,user=,command="], capture_output=True, text=True).stdout
    found = []
    for line in out.splitlines():
        parts = line.split(None, 2)
        if len(parts) == 3 and parts[1] == "root" and parts[2].startswith(iproxy + " "):
            found.append(int(parts[0]))
    return found


def password_ok(password):
    """先验证管理员密码（-k：不沿用缓存的授权），错了就不启动任何东西。"""
    if not password:
        return False
    try:
        r = subprocess.run(["sudo", "-S", "-k", "-v", "-p", ""], input=password + "\n",
                           capture_output=True, text=True, timeout=20)
    except subprocess.TimeoutExpired:
        return False
    return r.returncode == 0


# 宗卷会话：只在本次服务运行期间有效（重启后要重新识别，不沿用旧的默认值）。
#   identified：本次已从设备读取过实际分区（slots identify 成功退出）
#   volumes：{目标: {"version", "system", "data", "dp"}}，确认后才允许写盘阶段
VOL_SESSION = {"identified": False, "volumes": {}}
# 写盘阶段：必须先完成宗卷设置（会带上 --slot 与 --data-protection）
VOLUME_STAGES = {"volumes", "rootfs", "patch-rootfs", "install", "all"}


def start_privileged(args, body, what, on_exit=None):
    """需要 root 的阶段：已是 root 直接跑；否则要密码（need-sudo）、校验（bad-password）后经 sudo 跑。"""
    if not need_root():
        return {"ok": RUNNER.start(args, on_exit=on_exit)}
    password = body.get("password")
    if not password:
        return {"ok": False, "reason": "need-sudo"}
    if not password_ok(password):
        RUNNER.put(f"[!] {what}：管理员密码不正确。\n")
        return {"ok": False, "reason": "bad-password"}
    ok = RUNNER.start(args, password=password, on_exit=on_exit)
    return {"ok": ok, "reason": "" if ok else "busy"}

# raw 字符串：内嵌 JS 的 \n 与正则不能被 Python 提前转义。
PAGE = r"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark">
<link rel="icon" href="data:,">
<title>n56-patcher</title><style>
:root{color-scheme:dark;
 --ink:#0f0e0b;--plate:#191714;--plate2:#221f1a;--plate3:#2c2821;--line:#332e26;--line2:#4d473b;
 --fg:#efe9db;--mut:#a39a88;--amber:#ffb000;--amber2:#ffc94d;--on-amber:#1c1400;
 --ok:#9bd36a;--red:#ff7a5c;--red-solid:#d4371f;--red-hover:#e8472d;
 --amber-a:rgba(255,176,0,.12);--red-a:rgba(255,122,92,.12);
 --sans:-apple-system,BlinkMacSystemFont,"SF Pro Text","PingFang SC","Hiragino Sans GB","Microsoft YaHei","Segoe UI",sans-serif;
 --mono:ui-monospace,"SF Mono",SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace}
:root:lang(zh-TW){--sans:-apple-system,BlinkMacSystemFont,"SF Pro Text","PingFang TC","Hiragino Sans CNS","Microsoft JhengHei","Segoe UI",sans-serif}
:root:lang(ja){--sans:-apple-system,BlinkMacSystemFont,"SF Pro Text","Hiragino Sans","Hiragino Kaku Gothic ProN","Yu Gothic UI",Meiryo,"Segoe UI",sans-serif}
:root:lang(en){--sans:-apple-system,BlinkMacSystemFont,"SF Pro Text","Segoe UI",Roboto,sans-serif}
*{box-sizing:border-box}
[hidden]{display:none!important}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--ink);color:var(--fg);font:14px/1.5 var(--sans)}
button,input,select{font:inherit;color:inherit}
button{cursor:pointer}
button:disabled{cursor:not-allowed}
:focus-visible{outline:2px solid var(--amber);outline-offset:2px}
h1,h2,h3,p,ol,ul,dl,dd,menu{margin:0;padding:0}
ol,ul{list-style:none}
code{font-family:var(--mono);font-size:.93em}
.ic{display:inline-flex;width:14px;height:14px;flex:none}
.ic svg{width:100%;height:100%;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
.lab{font:600 11px/1.3 var(--mono);letter-spacing:.14em;color:var(--mut);text-transform:uppercase}

/* 控件 */
.sel{position:relative;display:block;min-width:0}
.sel::after{content:"";position:absolute;right:10px;top:50%;width:6px;height:6px;margin-top:-5px;
 border:solid var(--mut);border-width:0 1.5px 1.5px 0;transform:rotate(45deg);pointer-events:none}
select,input[type=text],input[type=password]{width:100%;height:32px;padding:0 10px;background:var(--ink);
 border:1px solid var(--line2);border-radius:2px;transition:border-color .12s}
select{appearance:none;-webkit-appearance:none;padding-right:28px;cursor:pointer;font-family:var(--mono);font-size:12.5px}
select:hover,input[type=text]:hover,input[type=password]:hover{border-color:var(--mut)}
input[type=text]{font-family:var(--mono);font-size:12.5px}
input[type=text]::placeholder{color:#857d6d;font-family:var(--sans)}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;height:32px;padding:0 12px;white-space:nowrap;
 background:var(--plate2);border:1px solid var(--line2);border-radius:2px;transition:background .12s,border-color .12s,color .12s}
.btn:hover:not(:disabled){background:var(--plate3);border-color:var(--mut)}
.btn:disabled{opacity:.45}
.btn.sm{height:26px;padding:0 8px;font-size:12px;color:var(--mut)}
.btn.sm:hover:not(:disabled){color:var(--fg)}
.btn.primary{background:var(--amber);border-color:var(--amber);color:var(--on-amber);font-weight:650}
.btn.primary:hover:not(:disabled){background:var(--amber2);border-color:var(--amber2)}
.btn.danger{background:var(--red-solid);border-color:var(--red-solid);color:#fff;font-weight:650}
.btn.danger:hover:not(:disabled){background:var(--red-hover);border-color:var(--red-hover)}
.sw{position:relative;flex:none;display:block;width:32px;height:18px;border:1px solid var(--line2);border-radius:2px;background:var(--ink);transition:background .14s,border-color .14s}
.sw::after{content:"";position:absolute;left:2px;top:2px;width:12px;height:12px;border-radius:1px;background:var(--mut);transition:transform .14s,background .14s}
input:checked+.sw{background:var(--amber-a);border-color:var(--amber)}
input:checked+.sw::after{transform:translateX(14px);background:var(--amber)}
input:focus-visible+.sw{outline:2px solid var(--amber);outline-offset:2px}
.tag{display:inline-flex;align-items:center;height:18px;padding:0 5px;border-radius:2px;font-size:11px;font-weight:600;line-height:1;white-space:nowrap}
.tag.must{background:var(--amber);color:var(--on-amber)}
.tag.edit{border:1px solid rgba(255,176,0,.6);color:var(--amber)}
.tag.danger{background:var(--red-solid);color:#fff}
.tag.opt{border:1px dashed var(--line2);color:var(--mut);font-weight:500}
.tag.dry{background:var(--amber-a);color:var(--amber);font-family:var(--mono)}

/* 顶栏 */
.top{position:sticky;top:0;z-index:6;display:flex;flex-wrap:wrap;align-items:center;gap:8px 16px;padding:10px 16px;
 background:var(--plate);border-bottom:1px solid var(--line)}
.plate{display:flex;align-items:center;gap:12px;margin-right:auto;min-width:0}
.model{padding:1px 7px;background:var(--amber);border-radius:2px;color:var(--on-amber);font:800 19px/1.35 var(--mono);letter-spacing:.02em}
.plate h1{font:650 14px/1.25 var(--mono)}
.plate div span{display:block;color:var(--mut);font-size:12px;line-height:1.3;white-space:nowrap}
.tgt{display:flex;align-items:center;gap:8px}
.tgt .sel{width:150px}
.tgt .sel.lang{width:112px}
.readout{display:flex;align-items:center;gap:9px;min-width:0;max-width:400px;height:32px;padding:0 10px;
 background:var(--ink);border:1px solid var(--line);border-radius:2px;font-size:12.5px;color:var(--mut)}
.readout i{flex:none;width:8px;height:8px;border-radius:50%;background:var(--line2)}
.readout b{min-width:0;font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.readout time{flex:none;padding-left:9px;border-left:1px solid var(--line);font:13px var(--mono);font-variant-numeric:tabular-nums;color:var(--mut)}
.readout[data-s=run]{color:var(--fg);border-color:rgba(255,176,0,.55)}
.readout[data-s=run] i{background:var(--amber);box-shadow:0 0 8px var(--amber);animation:pulse 1.4s ease-in-out infinite}
.readout[data-s=run] time{color:var(--amber)}
.readout[data-s=ok] i{background:var(--ok);box-shadow:0 0 6px var(--ok)}
.readout[data-s=ok]{color:var(--fg)}
.readout[data-s=fail]{color:#ffc0b1;border-color:rgba(255,122,92,.55)}
.readout[data-s=fail] i{background:var(--red);box-shadow:0 0 8px var(--red)}
.readout[data-s=stop] i{background:var(--fg)}
.readout[data-s=off]{color:var(--amber)}
.readout[data-s=off] i{background:var(--amber)}
@keyframes pulse{50%{opacity:.35}}
.btn.stop:not(:disabled){background:var(--red-solid);border-color:var(--red-solid);color:#fff;font-weight:650}
.btn.stop:hover:not(:disabled){background:var(--red-hover);border-color:var(--red-hover)}

/* 启动链 */
.chainbar{padding:10px 16px 0;background:var(--plate);border-bottom:1px solid var(--line)}
.ph{display:flex;flex-wrap:wrap;align-items:center;gap:4px 10px;min-height:26px}
.ph h2{font:650 12.5px/1.3 var(--sans)}
.ph small{color:var(--mut);font-size:12px}
.ph .end{margin-left:auto;display:flex;flex-wrap:wrap;gap:6px}
.chain{display:grid;grid-template-columns:repeat(8,minmax(0,1fr));margin-top:8px;
 background:repeating-linear-gradient(90deg,var(--line) 0 1px,transparent 1px 8px) 0 0/100% 5px no-repeat}
.chain li{position:relative;min-width:0}
.chain li:not(:last-child)::after{content:"";position:absolute;z-index:0;left:calc(10px + 8px);right:calc(-10px - 8px);top:25px;height:2px;background:var(--line2)}
.chain li.done:not(:last-child)::after{background:var(--ok)}
.chain li.running:not(:last-child)::after{background:repeating-linear-gradient(90deg,var(--amber) 0 6px,transparent 6px 12px);background-size:24px 2px;animation:trace .7s linear infinite}
@keyframes trace{to{background-position:24px 0}}
.node{position:relative;display:grid;align-content:start;justify-items:start;gap:1px;width:100%;height:100%;padding:17px 10px 11px;text-align:left;
 background:transparent;border:0;border-top:2px solid transparent;transition:background .12s}
.node:hover:not(.sel-on){background:var(--plate2)}
.node:focus-visible{outline-offset:-2px;z-index:2}
.node.sel-on{background:var(--plate3);border-top-color:var(--amber)}
.node.in-combo{background:var(--red-a)}
.node.in-combo.sel-on{background:var(--plate3)}
.pad{position:relative;z-index:1;display:inline-flex;align-items:center;justify-content:center;width:16px;height:16px;margin-bottom:6px;
 background:var(--plate);border:1.5px solid var(--mut);border-radius:2px;color:var(--ink)}
.pad .ic{width:12px;height:12px}
.pad .ic svg{stroke-width:2.6}
.t-opt .pad{border-style:dashed}
.t-must .pad{border-color:var(--amber)}
.t-edit .pad{border-color:var(--amber)}
.t-danger .pad{border-color:var(--red)}
.pad.r-ok{background:var(--ok);border-color:var(--ok);border-style:solid}
.pad.r-dry{color:var(--ok);border-color:var(--ok);border-style:dashed}
.pad.r-fail{background:var(--red);border-color:var(--red);border-style:solid}
.pad.r-stop{background:var(--fg);border-color:var(--fg);border-style:solid}
.pad.r-run{background:var(--amber);border-color:var(--amber);border-style:solid;box-shadow:0 0 10px var(--amber);animation:pulse 1.4s ease-in-out infinite}
.n-num{font:11px/1.4 var(--mono);color:var(--mut)}
.n-name{font-size:13.5px;font-weight:600;line-height:1.3}
.n-id{font:11px/1.45 var(--mono);color:var(--mut);overflow-wrap:anywhere}
.node .tag{margin-top:6px}

/* 工作区 */
.bench{display:grid;grid-template-columns:minmax(0,1fr)}
.step{padding:14px 16px 16px;background:var(--plate);border-bottom:1px solid var(--line);scroll-margin-top:110px}
.sthead{display:grid;grid-template-columns:auto minmax(0,1fr);column-gap:12px;align-items:start}
.stnum{font:300 42px/1 var(--mono);color:var(--amber);letter-spacing:-.04em}
.sthead h2{font-size:18px;font-weight:650;line-height:1.3}
.stmeta{display:flex;flex-wrap:wrap;align-items:center;gap:4px 7px;margin-top:2px;color:var(--mut);font:12px var(--mono)}
.stnote{margin-top:10px;font-size:13px;color:var(--fg)}
.spec{display:grid;grid-template-columns:auto minmax(0,1fr);gap:0 14px;margin-top:12px;border-top:1px solid var(--line);font-size:12.5px}
.spec dt,.spec dd{padding:6px 0;border-bottom:1px solid var(--line)}
.spec dt{color:var(--mut)}
.spec dd{overflow-wrap:anywhere}
.spec dd.v-ok{color:var(--ok)}.spec dd.v-fail{color:var(--red)}.spec dd.v-run{color:var(--amber)}
.spec dd.v-warn{color:#ffb7a5}
#run{width:100%;height:42px;margin-top:14px;font-size:14px;scroll-margin-bottom:96px}
.stage-danger{position:relative}
.stage-danger::before{content:"";display:block;height:4px;margin-bottom:10px;background:repeating-linear-gradient(135deg,var(--red-solid) 0 7px,transparent 7px 14px)}
.notice{display:flex;gap:8px;align-items:flex-start;margin-bottom:12px;padding:8px 10px;border:1px solid rgba(255,176,0,.5);border-radius:2px;background:var(--amber-a);font-size:12.5px}
.notice>.ic{color:var(--amber);margin-top:3px}
.notice div{flex:1;min-width:0;overflow-wrap:anywhere}
.notice button{flex:none;padding:0 4px;background:none;border:0;color:var(--mut);font-size:16px;line-height:1.2}
.combos{margin-top:18px}
.combos ul{display:grid;gap:6px;margin-top:6px}
.combo{display:grid;grid-template-columns:18px minmax(0,1fr) 16px;gap:8px;align-items:center;width:100%;padding:7px 9px;text-align:left;
 background:transparent;border:1px solid var(--line);border-left:3px solid var(--red-solid);border-radius:2px;transition:background .12s,border-color .12s}
.combo:hover{background:var(--plate2)}
.combo.sel-on{background:var(--red-a);border-color:rgba(255,122,92,.6);border-left-color:var(--red)}
.combo b{display:block;font-size:13px;font-weight:600}
.combo small{display:block;color:var(--mut);font-size:11.5px;line-height:1.35}
.combo-id{font:12px var(--mono);color:var(--red)}
.combo .pad{width:14px;height:14px;margin:0}

/* 控制台 */
.console{display:flex;flex-direction:column;min-width:0;padding:10px 16px 12px;scroll-margin-top:110px}
.logwrap{position:relative;flex:1;height:60vh;min-height:300px;margin-top:6px}
#log{height:100%;overflow:auto;padding:10px 12px;background:#080705;border:1px solid var(--line);border-radius:2px;
 font:12.5px/1.6 var(--mono);color:#d8d1c0;white-space:pre-wrap;overflow-wrap:anywhere;overscroll-behavior:contain}
#log:empty::before{content:attr(data-empty);color:var(--mut);font-family:var(--sans)}
#log>div{min-height:1.6em}
.l-ok{color:#b5e08f}.l-warn{color:var(--amber2)}.l-err{color:#ff9a82}.l-step{color:#b5e08f}
.l-cmd{color:#8f8676}
.l-run{margin-top:12px;padding-top:8px;border-top:1px dashed var(--line2)}
.l-run:first-child{margin-top:0;padding-top:0;border-top:0}
.l-end{font-weight:600}
.l-gap{color:var(--mut);font-style:italic}
.ltag{font-weight:700}
#jump{position:absolute;right:14px;bottom:12px;height:28px;background:var(--plate3);box-shadow:0 2px 10px rgba(0,0,0,.6)}
.q{gap:5px}
.q[aria-busy=true],.q[aria-busy=true]:disabled{opacity:1;color:var(--amber);border-color:rgba(255,176,0,.6)}
.q[data-r=ok] .ic{color:var(--ok)}.q[data-r=fail] .ic{color:var(--red)}

/* 底部状态条 */
.bar{position:sticky;bottom:0;z-index:5;display:flex;flex-wrap:wrap;align-items:center;gap:6px 14px;padding:8px 16px;
 background:var(--plate);border-top:1px solid var(--line)}
.fsum{display:flex;align-items:center;gap:8px;flex:0 1 auto;min-width:0;height:28px;padding:0 8px 0 0;background:none;border:0;text-align:left}
.fsum:hover b{color:var(--amber)}
.fsum b{flex:none;font:600 12.5px var(--mono);transition:color .12s}
#featlist{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--mut);font:12px var(--mono)}
.flags{display:flex;flex-wrap:wrap;align-items:center;gap:5px;margin-right:auto;min-width:0}
.flag{display:inline-flex;align-items:center;height:20px;padding:0 6px;border-radius:2px;font-size:11.5px;white-space:nowrap}
.flag.risk{background:var(--amber);color:var(--on-amber);font-weight:650}
.flag.info{border:1px solid var(--line2);color:var(--mut);font-family:var(--mono)}
.drysw{display:flex;align-items:center;gap:8px;cursor:pointer;font:12.5px var(--mono);color:var(--mut)}
.drysw input,.optrow input{position:absolute;opacity:0;width:1px;height:1px}
.drysw:has(input:checked){color:var(--amber)}

/* 选项抽屉 */
.drawer{width:min(440px,100vw);max-width:none;height:100dvh;max-height:none;margin:0 0 0 auto;padding:0;color:var(--fg);
 background:var(--plate);border:0;border-left:1px solid var(--line2)}
.drawer[open]{animation:slide .16s ease-out}
@keyframes slide{from{transform:translateX(24px);opacity:0}}
.drawer::backdrop{background:rgba(8,7,5,.6)}
.dw{display:flex;flex-direction:column;height:100%}
.dwh{display:flex;align-items:center;justify-content:space-between;padding:12px 16px;border-bottom:1px solid var(--line)}
.dwh h2{font-size:15px;font-weight:650}
.dwb{flex:1;overflow:auto;padding:0 16px 20px}
.dws{padding:14px 0;border-bottom:1px solid var(--line)}
.dws:last-child{border-bottom:0}
.dws .ph{margin-bottom:6px}
.optrow{display:grid;grid-template-columns:minmax(0,1fr) auto;align-items:center;gap:12px;padding:7px 0;cursor:pointer}
.optrow b{display:block;font:500 13px var(--mono)}
.optrow em{display:block;font-style:normal;color:var(--mut);font-size:12px}
.field{display:block;margin-top:10px}
.field>span:first-child{display:block;margin-bottom:4px;color:var(--mut);font-size:12px}
.chips{display:flex;flex-wrap:wrap;gap:5px}
.chip{position:relative;cursor:pointer}
.chip input{position:absolute;opacity:0;width:1px;height:1px}
.chip span{display:inline-flex;align-items:center;gap:6px;height:28px;padding:0 9px;border:1px solid var(--line2);border-radius:2px;
 font:12.5px var(--mono);color:var(--mut);transition:background .12s,border-color .12s,color .12s}
.chip span::before{content:"";width:8px;height:8px;border:1.5px solid var(--mut);border-radius:1px}
.chip:hover span{color:var(--fg);border-color:var(--mut)}
.chip input:checked+span{background:var(--amber-a);border-color:rgba(255,176,0,.6);color:var(--fg)}
.chip input:checked+span::before{background:var(--amber);border-color:var(--amber)}
.chip input:focus-visible+span{outline:2px solid var(--amber);outline-offset:2px}
.chip.dev span::after{content:attr(data-dev);font:10.5px var(--sans);color:var(--amber)}
.hint{margin-top:8px;color:var(--mut);font-size:12px}

/* 确认 */
.confirm{width:min(480px,calc(100vw - 32px));padding:0;color:var(--fg);background:var(--plate);border:1px solid var(--red);border-radius:3px}
.confirm::before{content:"";display:block;height:8px;background:repeating-linear-gradient(135deg,var(--red-solid) 0 9px,transparent 9px 18px)}
.confirm[data-sev=edit]{border-color:var(--amber)}
.confirm[data-sev=edit]::before{background:repeating-linear-gradient(135deg,var(--amber) 0 9px,transparent 9px 18px)}
.confirm[data-sev=edit] .btn.go{background:var(--amber);border-color:var(--amber);color:var(--on-amber)}
.confirm[data-sev=edit] .btn.go:hover:not(:disabled){background:var(--amber2);border-color:var(--amber2)}
.confirm[data-sev=edit] h3 .ic{color:var(--amber)}
.confirm::backdrop{background:rgba(8,7,5,.78)}
.dlg{padding:16px}
.dlg h3{display:flex;align-items:center;gap:8px;margin-bottom:6px;font-size:16px;font-weight:650}
.dlg h3 .ic{width:16px;height:16px;color:var(--red)}
.dlg p{margin-bottom:12px;color:var(--mut);font-size:13px}
.dlg dl{display:grid;grid-template-columns:auto minmax(0,1fr);gap:4px 12px;margin-bottom:14px;padding:10px 12px;background:var(--ink);font-size:12.5px}
.dlg dt{color:var(--mut)}
.dlg dd{font-family:var(--mono);overflow-wrap:anywhere}
.dlg menu{display:flex;justify-content:flex-end;gap:8px}

/* 宗卷设置弹窗 */
.modal{width:min(1000px,calc(100vw - 32px));max-width:none;max-height:min(88dvh,920px);padding:0;color:var(--fg);
 background:var(--plate);border:1px solid var(--line2);border-radius:3px}
.modal[open]{display:flex;flex-direction:column;animation:pop .14s ease-out}
@keyframes pop{from{transform:translateY(8px);opacity:0}}
.modal::backdrop{background:rgba(8,7,5,.7)}
.modal .dw{flex:1;min-height:0}
.dwh small{display:block;margin-top:2px;color:var(--mut);font-size:12px}
.mono{font-family:var(--mono)}
.tablewrap{overflow-x:auto;margin-top:4px}
.vt{width:100%;border-collapse:collapse;font-size:12.5px}
.vt th{padding:6px 8px;border-bottom:1px solid var(--line2);text-align:left;white-space:nowrap;
 font:600 11px/1.3 var(--mono);letter-spacing:.1em;color:var(--mut);text-transform:uppercase}
.vt td{padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:middle}
.vt .sel{min-width:150px;max-width:240px}
.vt select{height:26px}
.vacts{display:flex;flex-wrap:wrap;align-items:center;gap:4px}
.v-ok{color:var(--ok)}.v-warn{color:var(--amber)}.v-mut{color:var(--mut)}
.vkeep{display:inline-flex;align-items:center;gap:5px;height:26px;padding:0 4px;color:var(--mut);font-size:11.5px;cursor:pointer}
.vkeep input{accent-color:var(--amber)}
.vrow{display:flex;flex-wrap:wrap;align-items:center;gap:6px;margin-top:10px}
.vrow input[type=text]{width:72px}
.vrow .sel{width:220px}
.vrow code{font-size:12.5px}
.tag.okt{border:1px solid rgba(155,211,106,.6);color:var(--ok)}
#plan{margin-top:10px;padding:10px 12px;max-height:240px;overflow:auto;background:var(--ink);border:1px solid var(--line);
 border-radius:2px;font:12px/1.55 var(--mono);white-space:pre-wrap}
#pairs{white-space:pre-line}
.vfoot{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:8px;padding:10px 16px;border-top:1px solid var(--line)}
#vmsg{min-width:0;color:var(--amber);font-size:12.5px}
.dlg .field{margin:0 0 12px}
.dlg .pwerr{margin:-4px 0 12px;color:var(--red);font-size:12.5px}

.vform{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;margin-top:4px}
.vform .field{margin:0}
#vgate .hint{margin-top:4px}
@media(max-width:719px){.vform{grid-template-columns:minmax(0,1fr)}}

/* 响应式 */
@media(max-width:899px){.n-id{display:none}}
@media(min-width:720px){
 .top{flex-wrap:nowrap}
 .plate{flex:none}
 .tgt{flex:none}
 .readout{flex:0 1 400px}
 .btn.stop{flex:none}
}
@media(min-width:1000px){
 .bench{grid-template-columns:360px minmax(0,1fr)}
 .step{border-right:1px solid var(--line);border-bottom:0}
}
@media(min-width:1000px) and (min-height:640px){
 body{display:grid;grid-template-rows:auto auto minmax(0,1fr) auto;height:100vh;height:100dvh;overflow:hidden}
 .bench{min-height:0}
 .step{overflow:auto}
 .console{min-height:0}
 .logwrap{height:auto;min-height:0}
}
@media(max-width:719px){
 .top{padding:8px 16px}
 .plate{width:100%;margin:0}
 .tgt{flex:1 1 100%}.tgt .sel{flex:1;width:auto}
 .readout{flex:1;max-width:none}
 select,input[type=text],input[type=password]{height:40px;font-size:16px}
 .btn{height:40px}.btn.sm{height:32px}
 .drysw{min-height:32px}
 .chip span{height:34px}
 .optrow{padding:9px 0}
 .chain{grid-template-columns:minmax(0,1fr);background:none;margin-top:4px}
 .chain li:not(:last-child)::after{left:17px;right:auto;top:26px;bottom:-26px;width:2px;height:auto}
 .chain li.running:not(:last-child)::after{background:repeating-linear-gradient(0deg,var(--amber) 0 6px,transparent 6px 12px);animation:none}
 .node{grid-template-columns:16px 22px minmax(0,1fr) auto;gap:0 8px;align-items:center;min-height:44px;padding:8px 10px;border-top:0;border-left:2px solid transparent}
 .node.sel-on{border-left-color:var(--amber)}
 .pad{margin:0}
 .n-id{display:none}
 .node .tag{margin:0}
 .fsum{flex:1 1 40%}
 #featlist{display:none}
 .flags:empty{display:none}
 .flags{flex:1 1 100%;order:-1}
}
@media(prefers-reduced-motion:reduce){*,*::before,*::after{animation-duration:0s!important;transition:none!important}}
</style></head><body>
<svg width="0" height="0" style="position:absolute" aria-hidden="true">
 <symbol id="i-check" viewBox="0 0 16 16"><path d="M3 8.5l3.2 3.2L13 5"/></symbol>
 <symbol id="i-x" viewBox="0 0 16 16"><path d="M4 4l8 8M12 4l-8 8"/></symbol>
 <symbol id="i-warn" viewBox="0 0 16 16"><path d="M8 2.2L1.6 13.5h12.8L8 2.2zM8 6.5v3.2M8 11.7v.1"/></symbol>
 <symbol id="i-play" viewBox="0 0 16 16"><path d="M5 3l8 5-8 5z"/></symbol>
 <symbol id="i-stop" viewBox="0 0 16 16"><rect x="3.5" y="3.5" width="9" height="9" rx="1"/></symbol>
 <symbol id="i-eye" viewBox="0 0 16 16"><path d="M1.5 8S4 3.5 8 3.5 14.5 8 14.5 8 12 12.5 8 12.5 1.5 8 1.5 8z"/><circle cx="8" cy="8" r="1.8"/></symbol>
 <symbol id="i-down" viewBox="0 0 16 16"><path d="M8 3v9M4 8.5L8 12.5l4-4"/></symbol>
 <symbol id="i-lock" viewBox="0 0 16 16"><rect x="3" y="7" width="10" height="7" rx="1"/><path d="M5.5 7V5a2.5 2.5 0 015 0v2"/></symbol>
 <symbol id="i-vol" viewBox="0 0 16 16"><ellipse cx="8" cy="4" rx="5.5" ry="2"/><path d="M2.5 4v8c0 1.1 2.5 2 5.5 2s5.5-.9 5.5-2V4M2.5 8c0 1.1 2.5 2 5.5 2s5.5-.9 5.5-2"/></symbol>
 <symbol id="i-gear" viewBox="0 0 16 16"><path d="M2 4.5h7M12.5 4.5H14M2 11.5h1.5M7 11.5h7"/><circle cx="10.8" cy="4.5" r="1.7"/><circle cx="5.2" cy="11.5" r="1.7"/></symbol>
</svg>

<header class="top">
 <div class="plate"><span class="model">N56</span><div><h1>n56-patcher</h1><span data-i18n="sub"></span></div></div>
 <label class="tgt"><span class="lab" data-i18n="target"></span><span class="sel"><select id="target" autocomplete="off"></select></span></label>
 <label class="tgt"><span class="lab" data-i18n="lang"></span><span class="sel lang"><select id="lang" autocomplete="off"></select></span></label>
 <div class="readout" id="pill" data-s="idle"><i></i><b id="pilltext" role="status"></b><time id="pilltime">--:--</time></div>
 <button type="button" class="btn stop" id="stop" disabled><span class="ic"><svg viewBox="0 0 16 16" aria-hidden="true"><use href="#i-stop"></use></svg></span><span id="stoptext"></span></button>
</header>

<section class="chainbar" aria-labelledby="h-chain">
 <div class="ph"><h2 id="h-chain" data-i18n="chain"></h2><small data-i18n="chainHint"></small></div>
 <ol class="chain" id="chain"></ol>
</section>

<main class="bench">
 <section class="step" id="step" data-i18n-attr="aria-label:stepAria">
  <div class="notice" id="notice" hidden role="alert"><span class="ic"><svg viewBox="0 0 16 16" aria-hidden="true"><use href="#i-warn"></use></svg></span><div id="noticetext"></div><button type="button" id="noticex" data-i18n-attr="aria-label:closeNotice">×</button></div>
  <div id="stcard">
   <div class="sthead"><span class="stnum" id="stnum"></span><div><h2 id="sttitle"></h2><div class="stmeta" id="stmeta"></div></div></div>
   <p class="stnote" id="stnote"></p>
   <dl class="spec" id="stspec"></dl>
   <button type="button" class="btn primary" id="run"></button>
  </div>
  <div class="combos">
   <span class="lab" data-i18n="combos"></span>
   <ul id="combos"></ul>
  </div>
 </section>

 <section class="console" id="logpanel" aria-labelledby="h-log">
  <div class="ph"><h2 id="h-log" data-i18n="console"></h2><small id="logcount"></small>
   <span class="end"><span id="queries" style="display:contents"></span><button type="button" class="btn sm" id="logcopy" data-i18n="copy"></button><button type="button" class="btn sm" id="logclear" data-i18n="clear" data-i18n-attr="title:clearTitle"></button></span></div>
  <div class="logwrap"><div id="log" role="log" aria-live="off" tabindex="0" data-i18n-attr="data-empty:logEmpty"></div>
   <button type="button" class="btn sm" id="jump" hidden><span class="ic"><svg viewBox="0 0 16 16" aria-hidden="true"><use href="#i-down"></use></svg></span><span data-i18n="jump"></span></button></div>
 </section>
</main>

<footer class="bar">
 <button type="button" class="fsum" id="fsum" data-i18n-attr="title:openOpts"><span class="lab">Features</span><b id="featcount"></b><span id="featlist"></span></button>
 <div class="flags" id="flags"></div>
 <label class="drysw"><input type="checkbox" role="switch" id="dry" autocomplete="off"><span class="sw"></span>dry-run</label>
 <button type="button" class="btn sm" id="openopts"><span class="ic"><svg viewBox="0 0 16 16" aria-hidden="true"><use href="#i-gear"></use></svg></span><span data-i18n="options"></span></button>
</footer>

<dialog class="drawer" id="drawer" aria-labelledby="h-opts"><div class="dw">
 <div class="dwh"><h2 id="h-opts" data-i18n="options"></h2><button type="button" class="btn sm" id="closeopts" data-i18n="close"></button></div>
 <div class="dwb">
  <section class="dws" aria-labelledby="h-volsec">
   <div class="ph"><h2 id="h-volsec" data-i18n="vol.section"></h2><span class="end"><button type="button" class="btn sm" id="openvol"><span class="ic"><svg viewBox="0 0 16 16" aria-hidden="true"><use href="#i-vol"></use></svg></span><span data-i18n="volNav"></span></button></span></div>
   <p class="hint" id="volsum"></p>
  </section>
  <section class="dws" aria-labelledby="h-feat">
   <div class="ph"><h2 id="h-feat">Feature</h2><small id="featcount2"></small>
    <span class="end"><button type="button" class="btn sm" id="featdef" data-i18n="restore"></button><button type="button" class="btn sm" id="featall" data-i18n="selectAll"></button></span></div>
   <div class="chips" id="feats"></div>
   <p class="hint" id="featnone" data-i18n="featNone" hidden></p>
   <p class="hint" data-i18n="featHint"></p>
  </section>
  <section class="dws" id="jailbreaksection" aria-labelledby="h-jailbreak" hidden>
   <div class="ph"><h2 id="h-jailbreak" data-i18n="jbMode"></h2></div>
   <label class="field"><span data-i18n="jbMode"></span><select id="jailbreakmode" autocomplete="off" disabled>
    <option value="rootless" data-i18n="jbRootless"></option><option value="rootful" data-i18n="jbRootful"></option>
   </select></label>
   <p class="hint" data-i18n="jbHint"></p>
   <p class="hint" id="jailbreakwarning" data-i18n="jbPending" hidden></p>
  </section>
  <section class="dws" aria-labelledby="h-risk">
   <div class="ph"><h2 id="h-risk" data-i18n="risk"></h2></div>
   <label class="optrow"><span><b>allow-manual</b><em data-i18n="manualDesc"></em></span><input type="checkbox" role="switch" id="manual" autocomplete="off"><span class="sw"></span></label>
   <label class="optrow"><span><b data-i18n="noid"></b><em data-i18n="noidDesc"></em></span><input type="checkbox" role="switch" id="noid" autocomplete="off"><span class="sw"></span></label>
  </section>
  <section class="dws" aria-labelledby="h-input">
   <div class="ph"><h2 id="h-input" data-i18n="input"></h2></div>
   <label class="field"><span>N66 IPSW</span><input type="text" id="n66ipsw" data-i18n-attr="placeholder:ipswPh" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false"></label>
   <label class="field"><span>J96 IPSW</span><input type="text" id="j96ipsw" data-i18n-attr="placeholder:ipswPh" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false"></label>
   <label class="field"><span data-i18n="bootargs"></span><input type="text" id="bootargs" data-i18n-attr="placeholder:bootargsPh" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false"></label>
  </section>
 </div>
</div></dialog>

<dialog class="confirm" id="dlg" aria-labelledby="dlgtitle"><form method="dialog" class="dlg">
 <h3><span class="ic"><svg viewBox="0 0 16 16" aria-hidden="true"><use href="#i-warn"></use></svg></span><span id="dlgtitle"></span></h3>
 <p id="dlgnote"></p>
 <dl id="dlgrows"></dl>
 <menu><button class="btn" value="cancel" autofocus data-i18n="cancel"></button><button class="btn danger go" value="go" data-i18n="confirm"></button></menu>
</form></dialog>

<dialog class="confirm" id="pwdlg" data-sev="edit" aria-labelledby="pwtitle"><form method="dialog" class="dlg">
 <h3><span class="ic"><svg viewBox="0 0 16 16" aria-hidden="true"><use href="#i-lock"></use></svg></span><span id="pwtitle" data-i18n="pw.title"></span></h3>
 <p id="pwnote"></p>
 <label class="field"><span data-i18n="pw.label"></span><input type="password" id="pwinput" autocomplete="current-password"></label>
 <p class="pwerr" id="pwerr" data-i18n="pw.bad" role="alert" hidden></p>
 <menu><button class="btn" value="cancel" data-i18n="cancel"></button><button class="btn go" value="go" data-i18n="pw.go"></button></menu>
</form></dialog>

<dialog class="modal" id="vol" aria-labelledby="h-vol"><div class="dw">
 <div class="dwh"><div><h2 id="h-vol" data-v="title"></h2><small data-v="sub"></small></div><button type="button" class="btn sm" id="closevol" data-i18n="close"></button></div>
 <div class="dwb">
  <section class="dws" id="vgate"><div class="ph"><h2 data-v="gateTitle"></h2><span class="end"><button type="button" class="btn sm" id="btnIdentify" data-v="identify"></button></span></div>
   <p class="hint" id="vgatenote"></p><p class="hint" id="vunsupported" data-v="unsupported" hidden></p></section>
  <section class="dws" id="vplanbox" hidden><div class="ph"><h2 id="vplantitle"></h2><span class="end" id="vconfirmed"></span></div>
   <div class="vform">
    <label class="field"><span data-v="sysLabel"></span><span class="sel"><select id="vsys" autocomplete="off"></select></span></label>
    <label class="field"><span data-v="dataLabel"></span><span class="sel"><select id="vdata" autocomplete="off"></select></span></label>
    <label class="field"><span data-v="dpLabel"></span><span class="sel"><select id="vdp" autocomplete="off"></select></span></label>
   </div>
   <p class="hint" id="vplannote"></p>
   <div class="vrow"><button type="button" class="btn primary" id="btnConfirmVol" data-v="confirmVol"></button></div></section>
  <div id="vdetails" hidden>
   <section class="dws"><div class="ph"><h2 data-v="tDevice"></h2></div>
    <div class="vrow"><code id="deviceText"></code><span class="tag" id="donorBadge"></span><button type="button" class="btn sm" id="btnRebind" data-v="rebind"></button></div>
    <p class="hint" data-v="deviceHint"></p></section>
   <section class="dws"><div class="ph"><h2 data-v="tSlices"></h2></div>
    <div class="tablewrap"><table class="vt"><thead><tr><th data-v="cSlice"></th><th data-v="cPurpose"></th><th data-v="cContent"></th><th data-v="cPerm"></th><th data-v="cAction"></th></tr></thead><tbody id="slices"></tbody></table></div>
    <div class="vrow"><input type="text" id="newSlice" placeholder="s4" autocomplete="off" autocapitalize="off" spellcheck="false"><span class="sel"><select id="newPurpose" autocomplete="off"></select></span><button type="button" class="btn sm" id="btnAssign" data-v="assign"></button></div>
    <p class="hint" data-v="tHint"></p></section>
   <section class="dws"><div class="ph"><h2 data-v="tVersions"></h2></div>
    <div class="tablewrap"><table class="vt"><thead><tr><th data-v="vVersion"></th><th data-v="vStatus"></th><th data-v="vSlices"></th><th data-v="vAction"></th></tr></thead><tbody id="versions"></tbody></table></div>
    <pre id="plan" hidden></pre><p class="hint mono" id="pairs"></p></section>
   <section class="dws"><div class="ph"><h2 data-v="tDonor"></h2><span class="end"><button type="button" class="btn sm" id="btnVerify" data-v="verify"></button><button type="button" class="btn sm" id="btnSnapshot" data-v="snapshot"></button></span></div>
    <p class="hint" data-v="donorDeviceHint"></p></section>
  </div>
 </div>
 <div class="vfoot"><span id="vmsg" role="status"></span><button type="button" class="btn sm" id="vol2console" data-v="toConsole"></button></div>
</div></dialog>

<script>
const STAGES=%STAGES%;
const I18N={
 "zh-CN":{
  volNav:"宗卷设置","vol.section":"宗卷","vol.none":"未设置：执行写盘阶段时会先进入 ramdisk 读取设备分区，再弹出宗卷设置。","notice.volAuto":"正在进入 ramdisk 读取设备分区，读完会弹出宗卷设置，确认后继续{stage}。","notice.volFail":"读取设备分区失败，见控制台。","notice.volCancel":"已取消：{stage} 需要先确认宗卷设置。","dlg.clean":"端到端只适用于干净的设备：刚刷回 iOS 12.5.8，也没手动改过分区。设备上已经装过东西的，请改用分步执行，并先在宗卷设置里核对分区。","vol.summary":"iOS {v}：System s{sys} · Data s{data} · Data {dp}","btn.needVol":"先完成宗卷设置","spec.vol":"宗卷","notice.needVol":"{stage} 需要先完成宗卷设置。","pw.title":"需要输入密码","pw.note":"「{what}」需要管理员权限。本界面不是用 sudo 启动的，请输入这台 Mac 的登录密码。密码只用来启动这一次，不会保存。","pw.label":"密码","pw.go":"确定","pw.bad":"密码不对，请重试。","notice.pwCancel":"已取消：{stage} 需要管理员密码。",
  sub:"iPhone 6 Plus",lang:"语言",target:"目标",stop:"停止",stopping:"停止中…",
  chain:"启动链",chainHint:"节点状态只记录本次服务运行期间的结果，不代表设备实际状态",stepAria:"当前步骤",closeNotice:"关闭提示",
  combos:"一键组合",console:"控制台",copy:"复制",copied:"已复制",copyFail:"复制失败",clear:"清屏",clearTitle:"只清空显示，不影响后端缓冲",jump:"回到底部",logEmpty:"尚无输出。选中阶段并点击执行后，日志会显示在这里。",
  openOpts:"打开选项",options:"选项",close:"关闭",restore:"恢复默认",selectAll:"全选",featNone:"未选 feature：仅构建基础层。",featHint:"功能选择用于构建、自动构建启动和安装阶段，真实依赖自动补齐。",
  jbMode:"palera1n 布局",jbRootless:"rootless（推荐）",jbRootful:"rootful",jbHint:"iOS 15 及以上开启 palera1n 后可选；切换模式需重建启动包和 bootstrap。",jbPending:"此目标的 rootful 后端尚未实现：可选择或 dry-run，但禁止实际构建和写盘。",
  risk:"放宽检查",manualDesc:"执行标记为 manual 的 patch",noid:"不校验设备身份",noidDesc:"boot 时跳过身份检查",input:"输入与覆盖",dp:"Data 加密",dpDefaultEnc:"清单默认",ipswPh:"已导入 DMG 时可留空",bootargs:"boot-args 覆盖",bootargsPh:"留空用清单默认",
  cancel:"取消",confirm:"确认执行",modified:"改",
  "tag.sudo":"写盘 · sudo","tag.edit":"写设备","tag.must":"刷机后必做","tag.opt":"可选",
  "result.run":"运行中","result.ok":"成功","result.dry":"演练通过（未实际执行）","result.fail":"失败","result.stop":"已停止","result.none":"本次未运行",
  "spec.effect":"影响","spec.need":"前置","spec.perm":"权限","spec.result":"结果",permText:"需要管理员权限：未用 sudo 启动本界面时，执行前会弹窗输入密码（dry-run 不需要）",
  "btn.running":"运行中 · {stage}","btn.offline":"本地服务断开","btn.loading":"加载 feature…","btn.dry":"演练 {name}","btn.run":"执行 {name}",
  "pill.idle":"空闲","pill.off":"与本地服务断开，重连中…","pill.dryRun":"演练中 · {stage}","pill.run":"运行中 · {stage}","pill.starting":"正在启动…","pill.stage":"阶段","pill.dryOk":"演练通过","pill.ok":"完成","pill.stop":"已停止","pill.fail":"失败","pill.end":"{status} · {stage} · 退出码 {code}",
  "log.gap":"… 更早的 {n} 行已从显示中移除","log.lines":"{n} 行",
  "feat.base":"仅基础层","feat.changed":"已改","feat.loading":"加载中…","feat.loadFail":"feature 加载失败。","feat.none":"该目标没有可选 feature。",flagNoid:"跳过身份校验",
  "dlg.stage":"阶段","dlg.target":"目标","dlg.manifest":"清单默认","dlg.on":"开","dlg.titleEdit":"确认写设备：{name}","dlg.titleWipe":"确认写盘：{name}",
  "dlg.noteEdit":"此阶段会改动设备（新建/修改卷或向系统卷写入文件、改卷 role）。确认设备{ready}。","dlg.noteWipe":"此阶段会写入设备存储（rootfs 全量流写会先清空目标卷）。确认设备{ready}，运行期间不要断开连接。",
  "ready.ramdisk":"已进 ramdisk","ready.dfu":"处于 DFU",
  "notice.sudo":"当前未以 root 启动，{stage} 未执行（写盘需 root；dry-run 不受此限）。请退出后用 sudo python3 gui.py 重新启动本界面。","notice.req":"请求失败：{msg}","notice.stop":"停止请求失败：{msg}",
  s:{
   init:{short:"初始化",note:"补齐 donor（checkra1n、apfsios14）和 IPSW 派生输入，已有的跳过。首次需联网，并把 IPSW 放进 ipsw/。",effect:"只写本地 donors/、ipsw/cache/，不碰设备",need:"无"},
   ramdisk:{short:"进 ramdisk",note:"DFU → gaster → SSH ramdisk 就绪",effect:"引导 SSH ramdisk，不写设备存储",need:"设备处于 DFU"},
   "extract-im4m":{short:"重提 IM4M",label:"重提 IM4M（刷机后）",note:"读 NOR 重提本机 IM4M。刷机后必须执行，否则组件可能无法通过校验。",effect:"只读设备，写入本地 state/IM4M.bin",need:"ramdisk 已就绪"},
   volumes:{short:"建系统卷",note:"在容器内新建 System / Data 卷（role 0），卷号接在现有最大卷号之后。",effect:"写设备：新建卷",need:"ramdisk 已就绪"},
   rootfs:{short:"写 rootfs",note:"清空目标 System 卷后把所选版本的 rootfs 流式写入，约 20–30 分钟。",effect:"写设备：清空目标卷后全量写入",need:"ramdisk 已就绪"},
   "patch-rootfs":{short:"施加 patch",label:"施加 rootfs patch",note:"向系统卷写入 overlay（含越狱与 Cydia），完成收尾并改卷 role。",effect:"写设备：写入文件、改卷 role",need:"ramdisk 已就绪"},
   build:{short:"构建启动镜像",note:"iBSS / iBEC / DT / TC / KC → img4",effect:"只写本地 build 目录",need:"首次构建需设备处于 DFU（解密 iBSS、iBEC）"},
   boot:{short:"启动系统",note:"经 DFU 发送启动链，缺组件时先 build。",effect:"向设备发送启动链，不写设备存储",need:"设备处于 DFU"},
   all:{short:"端到端",note:"init（缺 iBSS/iBEC 时顺带解密）+ ramdisk + extract-im4m + volumes + rootfs + patch-rootfs + build + boot",effect:"写设备：清空目标卷后全量写入",need:"干净的设备（刚刷回 12.5.8、没手动改过分区），处于 DFU"},
   status:{short:"查看卷 role",note:"各卷 apfs_role · 需 ramdisk"},
   list:{short:"列出选挂",note:"当前选挂的 patch"}
  }
 },
 "en":{
  volNav:"Volumes","vol.section":"Volumes","vol.none":"Not set: disk-writing stages first enter ramdisk to read the device partitions, then open Volume settings.","notice.volAuto":"Entering ramdisk to read the device partitions. Volume settings will open when done; confirm them to continue with {stage}.","notice.volFail":"Reading the device partitions failed. See the console.","notice.volCancel":"Cancelled: {stage} needs confirmed volume settings.","dlg.clean":"End to end is only for a clean device: freshly restored to iOS 12.5.8, with no second system installed before and no manual partition changes. If the device already has anything installed, run the stages one by one and check the partitions in Volume settings first.","vol.summary":"iOS {v}: System s{sys} · Data s{data} · Data {dp}","btn.needVol":"Set up volumes first","spec.vol":"Volumes","notice.needVol":"{stage} needs volume settings first.","pw.title":"Password required","pw.note":"\"{what}\" needs administrator rights. This UI was not started with sudo, so enter the login password for this Mac. It is used only to start this run and is not stored.","pw.label":"Password","pw.go":"OK","pw.bad":"Incorrect password. Try again.","notice.pwCancel":"Cancelled: {stage} needs the administrator password.",
  sub:"iPhone 6 Plus",lang:"Language",target:"Target",stop:"Stop",stopping:"Stopping…",
  chain:"Boot chain",chainHint:"Node status only reflects results from this server session, not the actual device state",stepAria:"Current step",closeNotice:"Dismiss notice",
  combos:"Combos",console:"Console",copy:"Copy",copied:"Copied",copyFail:"Copy failed",clear:"Clear",clearTitle:"Clears the display only, not the server buffer",jump:"Back to bottom",logEmpty:"No output yet. Select a stage and run it to see logs here.",
  openOpts:"Open options",options:"Options",close:"Close",restore:"Restore defaults",selectAll:"Select all",featNone:"No features selected: only the base layer is built.",featHint:"Feature selection applies to the build, auto-build boot and install stages. Real dependencies are added automatically.",
  jbMode:"palera1n layout",jbRootless:"rootless (recommended)",jbRootful:"rootful",jbHint:"Available with palera1n on iOS 15+. Changing layout requires rebuilding boot artifacts and bootstrap.",jbPending:"Rootful is not implemented for this target: selection/dry-run is available, real builds and device writes are blocked.",
  risk:"Relaxed checks",manualDesc:"Run patches marked as manual",noid:"Skip device identity check",noidDesc:"Skips the identity check during boot",input:"Inputs and overrides",dp:"Data encryption",dpDefaultEnc:"Manifest default",ipswPh:"Optional if the DMG is already imported",bootargs:"boot-args override",bootargsPh:"Leave empty for the manifest default",
  cancel:"Cancel",confirm:"Run",modified:"edited",
  "tag.sudo":"Writes · sudo","tag.edit":"Writes device","tag.must":"Required after restore","tag.opt":"Optional",
  "result.run":"Running","result.ok":"Succeeded","result.dry":"Dry run passed (nothing executed)","result.fail":"Failed","result.stop":"Stopped","result.none":"Not run this session",
  "spec.effect":"Effect","spec.need":"Requires","spec.perm":"Permission","spec.result":"Result",permText:"Needs administrator rights: if this UI was not started with sudo, you will be asked for your password before it runs (not needed for dry-run)",
  "btn.running":"Running · {stage}","btn.offline":"Local server disconnected","btn.loading":"Loading features…","btn.dry":"Dry run: {name}","btn.run":"Run: {name}",
  "pill.idle":"Idle","pill.off":"Disconnected from local server, reconnecting…","pill.dryRun":"Dry run · {stage}","pill.run":"Running · {stage}","pill.starting":"Starting…","pill.stage":"Stage","pill.dryOk":"Dry run passed","pill.ok":"Done","pill.stop":"Stopped","pill.fail":"Failed","pill.end":"{status} · {stage} · exit code {code}",
  "log.gap":"… {n} earlier lines removed from the display","log.lines":"{n} lines",
  "feat.base":"Base layer only","feat.changed":"edited","feat.loading":"Loading…","feat.loadFail":"Failed to load features.","feat.none":"This target has no optional features.",flagNoid:"Identity check skipped",
  "dlg.stage":"Stage","dlg.target":"Target","dlg.manifest":"Manifest default","dlg.on":"On","dlg.titleEdit":"Confirm device write: {name}","dlg.titleWipe":"Confirm disk write: {name}",
  "dlg.noteEdit":"This stage changes the device: it creates or modifies volumes, or writes files to the second-system volumes and changes volume roles. Make sure the device {ready}.","dlg.noteWipe":"This stage writes to device storage, and the full rootfs stream wipes the target volume first. Make sure the device {ready}, and stay connected while it runs.",
  "ready.ramdisk":"is in ramdisk","ready.dfu":"is in DFU",
  "notice.sudo":"This server is not running as root, so {stage} did not run. Disk writes need root; dry-run does not. Quit and restart this UI with sudo python3 gui.py.","notice.req":"Request failed: {msg}","notice.stop":"Stop request failed: {msg}",
  s:{
   init:{short:"Initialize",note:"Prepares donors (checkra1n, apfsios14) and IPSW-derived inputs, skipping what already exists. First run needs network access and the IPSWs in ipsw/.",effect:"Writes only local donors/ and ipsw/cache/; does not touch the device",need:"Nothing"},
   ramdisk:{short:"Enter ramdisk",note:"DFU → gaster → SSH ramdisk ready",effect:"Boots the SSH ramdisk without writing device storage",need:"Device in DFU"},
   "extract-im4m":{short:"Re-extract IM4M",label:"Re-extract IM4M (after restore)",note:"Reads NOR to re-extract this device's IM4M. Required after a restore, or components may fail validation.",effect:"Reads the device and writes local state/IM4M.bin",need:"Ramdisk ready"},
   volumes:{short:"Create volumes",label:"Create System/Data volumes",note:"Creates the second system's System and Data volumes (role 0) after the highest existing volume number.",effect:"Writes device: creates volumes",need:"Ramdisk ready"},
   rootfs:{short:"Write rootfs",note:"Wipes the target System volume, then streams the selected version's rootfs. Takes about 20–30 minutes.",effect:"Writes device: wipes the target volume, then writes everything",need:"Ramdisk ready"},
   "patch-rootfs":{short:"Apply patches",label:"Apply rootfs patches",note:"Writes overlays (including the jailbreak and Cydia) to the second-system volumes, finishes setup and changes volume roles.",effect:"Writes device: writes files and changes volume roles",need:"Ramdisk ready"},
   build:{short:"Build images",label:"Build boot images",note:"iBSS / iBEC / DT / TC / KC → img4",effect:"Writes the local build directory only",need:"First build needs the device in DFU (to decrypt iBSS and iBEC)"},
   boot:{short:"Boot second system",note:"Sends the boot chain through DFU, building first if components are missing.",effect:"Sends the boot chain without writing device storage",need:"Device in DFU"},
   all:{short:"End to end",note:"init (also decrypts iBSS/iBEC if missing) + ramdisk + extract-im4m + volumes + rootfs + patch-rootfs + build + boot",effect:"Writes device: wipes the target volume, then writes everything",need:"A clean device (freshly restored to 12.5.8, no second system, no manual partition changes) in DFU"},
   status:{short:"Volume roles",note:"apfs_role of each volume · needs ramdisk"},
   list:{short:"List selection",note:"Currently selected patches"}
  }
 },
 "zh-TW":{
  volNav:"宗卷設定","vol.section":"宗卷","vol.none":"未設定：執行寫入磁碟的階段時會先進入 ramdisk 讀取裝置分區，再彈出宗卷設定。","notice.volAuto":"正在進入 ramdisk 讀取裝置分區，讀完會彈出宗卷設定，確認後繼續{stage}。","notice.volFail":"讀取裝置分區失敗，見主控台。","notice.volCancel":"已取消：{stage} 需要先確認宗卷設定。","dlg.clean":"端到端只適用於乾淨的裝置：剛刷回 iOS 12.5.8，也沒手動改過分區。裝置上已經裝過東西的，請改用分步執行，並先在宗卷設定裡核對分區。","vol.summary":"iOS {v}：System s{sys} · Data s{data} · Data {dp}","btn.needVol":"先完成宗卷設定","spec.vol":"宗卷","notice.needVol":"{stage} 需要先完成宗卷設定。","pw.title":"需要輸入密碼","pw.note":"「{what}」需要管理員權限。本介面不是用 sudo 啟動的，請輸入這台 Mac 的登入密碼。密碼只用來啟動這一次，不會儲存。","pw.label":"密碼","pw.go":"確定","pw.bad":"密碼不正確，請重試。","notice.pwCancel":"已取消：{stage} 需要管理員密碼。",
  sub:"iPhone 6 Plus",lang:"語言",target:"目標",stop:"停止",stopping:"停止中…",
  chain:"啟動鏈",chainHint:"節點狀態只記錄本次服務執行期間的結果，不代表裝置實際狀態",stepAria:"目前步驟",closeNotice:"關閉提示",
  combos:"一鍵組合",console:"主控台",copy:"複製",copied:"已複製",copyFail:"複製失敗",clear:"清除",clearTitle:"只清除顯示，不影響後端緩衝",jump:"回到底部",logEmpty:"尚無輸出。選取階段並點擊執行後，日誌會顯示在這裡。",
  openOpts:"開啟選項",options:"選項",close:"關閉",restore:"恢復預設",selectAll:"全選",featNone:"未選 feature：僅建置基礎層。",featHint:"功能選擇用於建置、自動建置啟動和安裝階段，實際相依項目自動補齊。",
  jbMode:"palera1n 佈局",jbRootless:"rootless（建議）",jbRootful:"rootful",jbHint:"iOS 15 以上啟用 palera1n 後可選；切換模式需重建啟動包與 bootstrap。",jbPending:"此目標的 rootful 後端尚未實作：可選擇或 dry-run，但禁止實際建置與寫入。",
  risk:"放寬檢查",manualDesc:"執行標記為 manual 的 patch",noid:"不驗證裝置身分",noidDesc:"boot 時略過身分檢查",input:"輸入與覆蓋",dp:"Data 加密",dpDefaultEnc:"清單預設",ipswPh:"已匯入 DMG 時可留空",bootargs:"boot-args 覆蓋",bootargsPh:"留空使用清單預設",
  cancel:"取消",confirm:"確認執行",modified:"改",
  "tag.sudo":"寫入磁碟 · sudo","tag.edit":"寫入裝置","tag.must":"刷機後必做","tag.opt":"選用",
  "result.run":"執行中","result.ok":"成功","result.dry":"演練通過（未實際執行）","result.fail":"失敗","result.stop":"已停止","result.none":"本次未執行",
  "spec.effect":"影響","spec.need":"前置","spec.perm":"權限","spec.result":"結果",permText:"需要管理員權限：未用 sudo 啟動本介面時，執行前會彈窗輸入密碼（dry-run 不需要）",
  "btn.running":"執行中 · {stage}","btn.offline":"本機服務已中斷","btn.loading":"載入 feature…","btn.dry":"演練 {name}","btn.run":"執行 {name}",
  "pill.idle":"閒置","pill.off":"與本機服務中斷，重新連線中…","pill.dryRun":"演練中 · {stage}","pill.run":"執行中 · {stage}","pill.starting":"正在啟動…","pill.stage":"階段","pill.dryOk":"演練通過","pill.ok":"完成","pill.stop":"已停止","pill.fail":"失敗","pill.end":"{status} · {stage} · 結束代碼 {code}",
  "log.gap":"… 更早的 {n} 行已從顯示中移除","log.lines":"{n} 行",
  "feat.base":"僅基礎層","feat.changed":"已改","feat.loading":"載入中…","feat.loadFail":"feature 載入失敗。","feat.none":"此目標沒有可選 feature。",flagNoid:"略過身分驗證",
  "dlg.stage":"階段","dlg.target":"目標","dlg.manifest":"清單預設","dlg.on":"開","dlg.titleEdit":"確認寫入裝置：{name}","dlg.titleWipe":"確認寫入磁碟：{name}",
  "dlg.noteEdit":"此階段會變更裝置（新建/修改磁碟區或向系統磁碟區寫入檔案、變更磁碟區 role）。請確認裝置{ready}。","dlg.noteWipe":"此階段會寫入裝置儲存空間（rootfs 全量串流寫入會先清空目標磁碟區）。請確認裝置{ready}，執行期間不要中斷連線。",
  "ready.ramdisk":"已進入 ramdisk","ready.dfu":"處於 DFU",
  "notice.sudo":"目前未以 root 啟動，{stage} 未執行（寫入磁碟需要 root；dry-run 不受此限）。請結束後用 sudo python3 gui.py 重新啟動本介面。","notice.req":"請求失敗：{msg}","notice.stop":"停止請求失敗：{msg}",
  s:{
   init:{short:"初始化",note:"補齊 donor（checkra1n、apfsios14）和 IPSW 衍生輸入，已有的會跳過。首次需連網，並把 IPSW 放進 ipsw/。",effect:"只寫入本機 donors/、ipsw/cache/，不碰裝置",need:"無"},
   ramdisk:{short:"進入 ramdisk",note:"DFU → gaster → SSH ramdisk 就緒",effect:"引導 SSH ramdisk，不寫入裝置儲存空間",need:"裝置處於 DFU"},
   "extract-im4m":{short:"重新提取 IM4M",label:"重新提取 IM4M（刷機後）",note:"讀取 NOR 重新提取本機 IM4M。刷機後必須執行，否則元件可能無法通過驗證。",effect:"唯讀裝置，寫入本機 state/IM4M.bin",need:"ramdisk 已就緒"},
   volumes:{short:"建立系統磁碟區",label:"建立 System/Data 磁碟區",note:"在容器內新建 System / Data 磁碟區（role 0），編號接在現有最大編號之後。",effect:"寫入裝置：新建磁碟區",need:"ramdisk 已就緒"},
   rootfs:{short:"寫入 rootfs",note:"清空目標 System 磁碟區後把所選版本的 rootfs 串流寫入，約 20–30 分鐘。",effect:"寫入裝置：清空目標磁碟區後全量寫入",need:"ramdisk 已就緒"},
   "patch-rootfs":{short:"套用 patch",label:"套用 rootfs patch",note:"向系統磁碟區寫入 overlay（含越獄與 Cydia），完成收尾並變更磁碟區 role。",effect:"寫入裝置：寫入檔案、變更磁碟區 role",need:"ramdisk 已就緒"},
   build:{short:"建置啟動映像",note:"iBSS / iBEC / DT / TC / KC → img4",effect:"只寫入本機 build 目錄",need:"首次建置需裝置處於 DFU（解密 iBSS、iBEC）"},
   boot:{short:"啟動系統",note:"經 DFU 傳送啟動鏈，缺元件時先 build。",effect:"向裝置傳送啟動鏈，不寫入裝置儲存空間",need:"裝置處於 DFU"},
   all:{short:"端到端",note:"init（缺 iBSS/iBEC 時順帶解密）+ ramdisk + extract-im4m + volumes + rootfs + patch-rootfs + build + boot",effect:"寫入裝置：清空目標磁碟區後全量寫入",need:"乾淨的裝置（剛刷回 12.5.8、沒手動改過分區），處於 DFU"},
   status:{short:"查看磁碟區 role",note:"各磁碟區 apfs_role · 需要 ramdisk"},
   list:{short:"列出選取項目",note:"目前選取的 patch"}
  }
 },
 "ja":{
  volNav:"ボリューム設定","vol.section":"ボリューム","vol.none":"未設定：書き込みステージの実行時に、まず ramdisk に入ってパーティションを読み取り、ボリューム設定を開きます。","notice.volAuto":"ramdisk に入ってデバイスのパーティションを読み取っています。終わるとボリューム設定が開きます。確定すると{stage}を続行します。","notice.volFail":"パーティションの読み取りに失敗しました。コンソールを確認してください。","notice.volCancel":"キャンセルしました：{stage} にはボリューム設定の確定が必要です。","dlg.clean":"エンドツーエンドはクリーンなデバイス専用です：iOS 12.5.8 を復元したばかりで、パーティションを手動で変更していないこと。すでに何か入っている場合は、ステージを一つずつ実行し、先にボリューム設定でパーティションを確認してください。","vol.summary":"iOS {v}：System s{sys} · Data s{data} · Data {dp}","btn.needVol":"先にボリューム設定","spec.vol":"ボリューム","notice.needVol":"{stage} の前にボリューム設定が必要です。","pw.title":"パスワードが必要です","pw.note":"「{what}」には管理者権限が必要です。この画面は sudo で起動されていないため、この Mac のログインパスワードを入力してください。パスワードは今回の起動にだけ使い、保存しません。","pw.label":"パスワード","pw.go":"OK","pw.bad":"パスワードが違います。もう一度入力してください。","notice.pwCancel":"キャンセルしました：{stage} には管理者パスワードが必要です。",
  sub:"iPhone 6 Plus",lang:"言語",target:"ターゲット",stop:"停止",stopping:"停止中…",
  chain:"ブートチェーン",chainHint:"ノードの状態はこのサーバー実行中の結果のみで、デバイスの実際の状態ではありません",stepAria:"現在のステップ",closeNotice:"通知を閉じる",
  combos:"ワンクリック",console:"コンソール",copy:"コピー",copied:"コピーしました",copyFail:"コピー失敗",clear:"クリア",clearTitle:"表示のみクリアし、サーバーのバッファには影響しません",jump:"一番下へ",logEmpty:"出力はまだありません。ステージを選択して実行すると、ここにログが表示されます。",
  openOpts:"オプションを開く",options:"オプション",close:"閉じる",restore:"デフォルトに戻す",selectAll:"すべて選択",featNone:"feature 未選択：ベースレイヤーのみビルドします。",featHint:"機能の選択はビルド、自動ビルド起動、インストールの各ステージに適用され、依存関係は自動で補完されます。",
  jbMode:"palera1n レイアウト",jbRootless:"rootless（推奨）",jbRootful:"rootful",jbHint:"iOS 15 以降で palera1n を有効にすると選択できます。変更時は起動ファイルと bootstrap の再ビルドが必要です。",jbPending:"このターゲットの rootful バックエンドは未実装です。選択と dry-run は可能ですが、実ビルドと書き込みは拒否されます。",
  risk:"チェックの緩和",manualDesc:"manual と指定された patch を実行",noid:"デバイス ID を検証しない",noidDesc:"boot 時に ID チェックをスキップ",input:"入力と上書き",dp:"Data 暗号化",dpDefaultEnc:"マニフェスト既定",ipswPh:"DMG をインポート済みなら空欄可",bootargs:"boot-args の上書き",bootargsPh:"空欄でマニフェスト既定を使用",
  cancel:"キャンセル",confirm:"実行する",modified:"変更",
  "tag.sudo":"書き込み · sudo","tag.edit":"デバイス書き込み","tag.must":"復元後に必須","tag.opt":"任意",
  "result.run":"実行中","result.ok":"成功","result.dry":"ドライラン成功（実行なし）","result.fail":"失敗","result.stop":"停止しました","result.none":"今回は未実行",
  "spec.effect":"影響","spec.need":"前提","spec.perm":"権限","spec.result":"結果",permText:"管理者権限が必要：この画面を sudo で起動していない場合は、実行前にパスワードの入力を求めます（dry-run では不要）",
  "btn.running":"実行中 · {stage}","btn.offline":"ローカルサーバーから切断","btn.loading":"feature を読み込み中…","btn.dry":"ドライラン：{name}","btn.run":"実行：{name}",
  "pill.idle":"待機中","pill.off":"ローカルサーバーから切断、再接続中…","pill.dryRun":"ドライラン中 · {stage}","pill.run":"実行中 · {stage}","pill.starting":"起動中…","pill.stage":"ステージ","pill.dryOk":"ドライラン成功","pill.ok":"完了","pill.stop":"停止しました","pill.fail":"失敗","pill.end":"{status} · {stage} · 終了コード {code}",
  "log.gap":"… 以前の {n} 行を表示から削除しました","log.lines":"{n} 行",
  "feat.base":"ベースレイヤーのみ","feat.changed":"変更あり","feat.loading":"読み込み中…","feat.loadFail":"feature の読み込みに失敗しました。","feat.none":"このターゲットに選択可能な feature はありません。",flagNoid:"ID 検証をスキップ",
  "dlg.stage":"ステージ","dlg.target":"ターゲット","dlg.manifest":"マニフェスト既定","dlg.on":"オン","dlg.titleEdit":"デバイス書き込みの確認：{name}","dlg.titleWipe":"ディスク書き込みの確認：{name}",
  "dlg.noteEdit":"このステージはデバイスを変更します（ボリュームの作成・変更、ボリュームへのファイル書き込み、ボリューム role の変更）。デバイスが{ready}ことを確認してください。","dlg.noteWipe":"このステージはデバイスのストレージに書き込みます（rootfs の全量書き込みでは先にターゲットボリュームを消去します）。デバイスが{ready}ことを確認し、実行中は接続を切らないでください。",
  "ready.ramdisk":"ramdisk に入っている","ready.dfu":"DFU 状態である",
  "notice.sudo":"root で起動していないため、{stage} は実行されませんでした（書き込みには root が必要です。dry-run は対象外です）。終了して sudo python3 gui.py で再起動してください。","notice.req":"リクエスト失敗：{msg}","notice.stop":"停止リクエスト失敗：{msg}",
  s:{
   init:{short:"初期化",note:"donor（checkra1n、apfsios14）と IPSW 由来の入力を用意します。既にあるものはスキップ。初回はネット接続と ipsw/ への IPSW 配置が必要です。",effect:"ローカルの donors/ と ipsw/cache/ のみ書き込み、デバイスには触れません",need:"なし"},
   ramdisk:{short:"ramdisk に入る",note:"DFU → gaster → SSH ramdisk 準備完了",effect:"SSH ramdisk を起動。デバイスのストレージには書き込みません",need:"デバイスが DFU 状態"},
   "extract-im4m":{short:"IM4M を再抽出",label:"IM4M を再抽出（復元後）",note:"NOR を読み取り、このデバイスの IM4M を再抽出します。復元後は必須で、実行しないとコンポーネントが検証を通らない場合があります。",effect:"デバイスは読み取りのみ。ローカルの state/IM4M.bin に書き込みます",need:"ramdisk 準備完了"},
   volumes:{short:"ボリュームを作成",label:"System/Data ボリュームを作成",note:"コンテナ内に System / Data ボリューム（role 0）を、既存の最大番号の後ろに作成します。",effect:"デバイス書き込み：ボリュームを作成",need:"ramdisk 準備完了"},
   rootfs:{short:"rootfs を書き込み",note:"ターゲットの System ボリュームを消去し、選択したバージョンの rootfs をストリーム書き込みします。約 20〜30 分かかります。",effect:"デバイス書き込み：ターゲットボリュームを消去して全量書き込み",need:"ramdisk 準備完了"},
   "patch-rootfs":{short:"patch を適用",label:"rootfs patch を適用",note:"ボリュームに overlay（脱獄と Cydia を含む）を書き込み、仕上げを行ってボリューム role を変更します。",effect:"デバイス書き込み：ファイル書き込み、ボリューム role の変更",need:"ramdisk 準備完了"},
   build:{short:"イメージをビルド",label:"ブートイメージをビルド",note:"iBSS / iBEC / DT / TC / KC → img4",effect:"ローカルの build ディレクトリのみ書き込み",need:"初回ビルドではデバイスを DFU にする必要があります（iBSS、iBEC の復号）"},
   boot:{short:"システムを起動",note:"DFU 経由でブートチェーンを送信します。コンポーネントが不足していれば先に build します。",effect:"ブートチェーンを送信。デバイスのストレージには書き込みません",need:"デバイスが DFU 状態"},
   all:{short:"エンドツーエンド",note:"init（iBSS/iBEC がなければ復号も）+ ramdisk + extract-im4m + volumes + rootfs + patch-rootfs + build + boot を実行",effect:"デバイス書き込み：ターゲットボリュームを消去して全量書き込み",need:"クリーンなデバイス（12.5.8 を復元したばかり、パーティション未変更）が DFU 状態"},
   status:{short:"ボリューム role",note:"各ボリュームの apfs_role · ramdisk が必要"},
   list:{short:"選択を一覧表示",note:"現在選択中の patch"}
  }
 }
};
const LANGS=[["zh-CN","简体中文"],["en","English"],["zh-TW","繁體中文"],["ja","日本語"]];
function detectLang(){
 try{const s=localStorage.getItem('n56-lang');if(I18N[s])return s}catch(e){}
 for(const l of navigator.languages||[navigator.language]){
  const x=(l||'').toLowerCase();
  if(/^zh-(tw|hk|mo|hant)/.test(x))return 'zh-TW';
  if(x.startsWith('zh'))return 'zh-CN';
  if(x.startsWith('ja'))return 'ja';
  if(x.startsWith('en'))return 'en';
 }
 return 'en';
}
let lang=detectLang();
function t(key,vars){
 const s=I18N[lang][key]??I18N['zh-CN'][key]??key;
 return vars?s.replace(/\{(\w+)\}/g,(m,k)=>k in vars?vars[k]:m):s;
}
const st=(id,f)=>(I18N[lang].s[id]||{})[f]||'';
function applyStatic(){
 document.documentElement.lang=lang;
 for(const e of document.querySelectorAll('[data-i18n]'))e.textContent=t(e.dataset.i18n);
 for(const e of document.querySelectorAll('[data-i18n-attr]')){
  for(const pair of e.dataset.i18nAttr.split(';')){
   const [attr,key]=pair.split(':');
   e.setAttribute(attr,t(key));
  }
 }
}
const TAG_CLASS_OF={sudo:'danger',edit:'edit',must:'must',opt:'opt'};
const META={
 init:{group:'flow'},
 ramdisk:{group:'flow'},
 'extract-im4m':{group:'flow',tone:'must',tag:'must'},
 volumes:{group:'flow',tone:'edit',confirm:1,sev:'edit',tag:'edit',ready:'ready.ramdisk'},
 rootfs:{group:'flow',tone:'danger',confirm:1,sev:'wipe',sudo:1,tag:'sudo',ready:'ready.ramdisk'},
 'patch-rootfs':{group:'flow',tone:'edit',confirm:1,sev:'edit',tag:'edit',ready:'ready.ramdisk'},
 build:{group:'flow'},
 boot:{group:'flow'},
 all:{group:'combo',num:'A',tone:'danger',confirm:1,sev:'wipe',sudo:1,tag:'sudo',members:['init','ramdisk','extract-im4m','volumes','rootfs','patch-rootfs','build','boot'],ready:'ready.dfu'},
 status:{group:'query'},
 list:{group:'query'}
};
const VOL_GATED=new Set(['volumes','rootfs','patch-rootfs','install','all']);
let volCfg=null;
let pendingRun=null;   // 等宗卷设置确认后继续执行的阶段 {stage, body}
const FEATURE_STAGES=new Set(['build','boot','patch-rootfs','install','all','list']);
const RESULT_TEXT={run:'v-run',ok:'v-ok',dry:'v-ok',fail:'v-fail',stop:''};
const MAX_LINES=5000;

const $=id=>document.getElementById(id);
function h(tag,attrs,...kids){
 const e=document.createElement(tag);
 for(const k in attrs||{}){
  if(k==='class')e.className=attrs[k];
  else if(k.startsWith('on'))e.addEventListener(k.slice(2),attrs[k]);
  else e.setAttribute(k,attrs[k]);
 }
 e.append(...kids.filter(x=>x!=null));
 return e;
}
function icon(name){
 const s=h('span',{class:'ic'});
 s.innerHTML='<svg viewBox="0 0 16 16" aria-hidden="true"><use href="#i-'+name+'"></use></svg>';
 return s;
}
async function j(u,o){
 const r=await fetch(u,o);
 if(!r.ok)throw new Error('HTTP '+r.status);
 return r.json();
}

/* ---------- 运行状态：全部从日志流推导，刷新页面后也能恢复 ---------- */
const FLOW=STAGES.filter(id=>(META[id]||{}).group==='flow');
const state={active:null,sub:null,activeDry:false,pending:false,stopping:false,online:true,startedAt:0,last:null,results:{}};
let stopTimer=0,selected=FLOW[0],replaying=true,stepKey='';
const RUN_LINE=/^\$ .*n56patcher\.py (\S+)/,END_LINE=/阶段结束，退出码 (-?\d+)/,SUB_LINE=/^\[>\] (\S+)/;
const label=id=>st(id,'label')||st(id,'short')||id;
const rows={};
const title=id=>st(id,'short')||id;
const tagEl=m=>h('span',{class:'tag '+TAG_CLASS_OF[m.tag]},t('tag.'+m.tag));

function nextFlow(id){
 const i=FLOW.indexOf(id);
 if(i<0)return null;
 return FLOW.slice(i+1).find(s=>!META[s].opt)||null;
}
function markSub(kind){
 if(state.sub)state.results[state.sub]=kind==='ok'&&state.activeDry?'dry':kind;
}
function enterSub(id){
 if(!((META[state.active]||{}).members||[]).includes(id))return;
 markSub('ok');
 state.sub=id;state.subN=(state.subN||0)+1;state.results[id]='run';
}
// 端到端运行时带上当前子阶段和进度，其他阶段只显示 ID
function activeName(){
 if(!state.sub)return state.active;
 const ms=META[state.active].members;
 return label(state.active)+' · '+title(state.sub)+' · '+state.subN+'/'+ms.length;   // 按实际进入顺序计数（15 的 build 排在 rootfs 之前）
}
function trackLine(line){
 let m;
 if((m=line.match(RUN_LINE))){
  state.active=m[1];state.activeDry=line.includes(' --dry-run');
  state.startedAt=Date.now();state.results[m[1]]='run';state.last=null;follow=true;state.sub=null;state.subN=0;
  for(const s of (META[m[1]]||{}).members||[])delete state.results[s];
  if(replaying&&(META[m[1]]||{}).group!=='query')selected=m[1];
 }else if((m=line.match(END_LINE))){
  finish(+m[1]);
 }else if((m=line.match(SUB_LINE))){
  enterSub(m[1]);
 }else if(line.includes('[ERROR] 启动失败')){
  finish(1);
 }
}
function finish(code){
 const stage=state.active;
 const kind=code===0?'ok':(code<0||code===130||state.stopping)?'stop':'fail';
 if(stage)state.results[stage]=kind==='ok'&&state.activeDry?'dry':kind;
 markSub(kind);state.sub=null;
 state.last={stage,code,kind,dry:state.activeDry};
 state.active=null;state.stopping=false;clearTimeout(stopTimer);
 // 成功后选中下一步（只选中，不运行）；用户已切到别的阶段时不打扰
 if(kind==='ok'&&stage===selected){const n=nextFlow(stage);if(n)selected=n}
 vload();
 // 自动读分区的那次识别结束：成功就弹出宗卷设置，失败就放弃这次执行
 if(pendingRun&&stage==='slots'&&!replaying){
  if(code===0)openVol();
  else{pendingRun=null;notice('notice.volFail')}
 }
}
function isBusy(){return state.pending||!!state.active||!state.online||!$('target').value}
function fmtTime(ms){
 const s=Math.max(0,Math.floor(ms/1000)),p=n=>String(n).padStart(2,'0');
 return (s>=3600?Math.floor(s/3600)+':':'')+p(Math.floor(s/60)%60)+':'+p(s%60);
}
function tickTimer(){
 $('pilltime').textContent=state.active?fmtTime(Date.now()-state.startedAt):'--:--';
}
function setPad(pad,res){
 pad.className='pad'+(res?' r-'+res:'');
 const name={ok:'check',dry:'check',fail:'x',stop:'stop'}[res];
 if(pad.dataset.ic!==(name||'')){
  pad.dataset.ic=name||'';
  pad.replaceChildren(...(name?[icon(name)]:[]));
 }
}
function renderStep(){
 const m=META[selected]||{},res=state.results[selected];
 const key=lang+'|'+selected+'|'+res+'|'+volText();
 if(key!==stepKey){
  stepKey=key;
  const idx=FLOW.indexOf(selected);
  $('stcard').className=m.tone==='danger'?'stage-danger':'';
  $('stnum').textContent=m.num||String(idx).padStart(2,'0');
  $('sttitle').textContent=title(selected);
  $('stmeta').replaceChildren(selected,...(m.tag?[tagEl(m)]:[]));
  $('stnote').textContent=st(selected,'note');
  const specs=[[t('spec.effect'),st(selected,'effect'),m.tone==='danger'?'v-warn':''],[t('spec.need'),st(selected,'need'),'']];
  if(m.sudo)specs.push([t('spec.perm'),t('permText'),'']);
  if(VOL_GATED.has(selected))specs.push([t('spec.vol'),volText(),'']);
  specs.push([t('spec.result'),t('result.'+(res in RESULT_TEXT?res:'none')),RESULT_TEXT[res]||'']);
  $('stspec').replaceChildren(...specs.flatMap(([k,v,c])=>[h('dt',null,k),h('dd',{class:c},v)]));
 }
 const busy=isBusy(),notReady=FEATURE_STAGES.has(selected)&&!featsReady,dry=$('dry').checked,btn=$('run');
 btn.disabled=busy||notReady;
 btn.className='btn '+(m.tone==='danger'&&!dry?'danger':'primary');
 const text=state.active?t('btn.running',{stage:activeName()}):!state.online?t('btn.offline'):notReady?t('btn.loading'):t(dry?'btn.dry':'btn.run',{name:title(selected)});
 if(btn.dataset.text!==text){
  btn.dataset.text=text;
  btn.replaceChildren(icon('play'),h('span',null,text));
 }
}
function render(){
 const busy=isBusy();
 const combo=[...((META[selected]||{}).members||[]),...((META[state.active]||{}).members||[])];
 for(const id in rows){
  const {btn,pad,li}=rows[id],res=state.results[id],running=state.active===id||state.sub===id,on=selected===id;
  if(pad)setPad(pad,running?'run':res==='run'?'':res);
  if(btn.classList.contains('q')){
   btn.disabled=busy||(FEATURE_STAGES.has(id)&&!featsReady);
   btn.dataset.r=res==='run'?'':res||'';
  }else{
   btn.classList.toggle('sel-on',on);
   btn.setAttribute('aria-pressed',on?'true':'false');
   btn.classList.toggle('in-combo',combo.includes(id));
  }
  btn.setAttribute('aria-busy',running?'true':'false');
  if(li){
   li.classList.toggle('done',res==='ok'||res==='dry');
   li.classList.toggle('running',running);
  }
 }
 renderStep();
 $('stop').disabled=!state.active||state.stopping||!state.online;
 $('stoptext').textContent=t(state.stopping?'stopping':'stop');
 let s='idle',text=t('pill.idle');
 if(!state.online){s='off';text=t('pill.off')}
 else if(state.active){s='run';text=t(state.activeDry?'pill.dryRun':'pill.run',{stage:activeName()})}
 else if(state.pending){s='run';text=t('pill.starting')}
 else if(state.last){
  s=state.last.kind;
  const name=state.last.stage||t('pill.stage');
  text=t('pill.end',{status:t(s==='ok'?(state.last.dry?'pill.dryOk':'pill.ok'):s==='stop'?'pill.stop':'pill.fail'),stage:name,code:state.last.code});
 }
 const pill=$('pill');
 pill.dataset.s=s;
 if($('pilltext').textContent!==text)$('pilltext').textContent=text;
 tickTimer();
 document.title=(state.active?'▶ '+activeName()+' — ':'')+'n56-patcher';
}
function select(id){
 selected=id;
 render();
 if(matchMedia('(max-width:999px)').matches)$('run').scrollIntoView({block:'nearest'});
}

/* ---------- 日志 ---------- */
const logEl=$('log');
let off=0,tail='',tailEl=null,progEl=null,follow=true,lineCount=0,dropped=0,gapEl=null,inflight=null;
const ANSI=/\x1b\[[0-9;]*[A-Za-z]/g;
const PROG=/^\s*(\[[=#>\s-]*\]\s*[\d.]+%|[\d.]+%\s*\[[=#>\s-]*\])\s*$/;   // 进度条：连续的只占一行
const TAG=/^(\s*)(\[\*\]|\[!\]|\[>\]|\[ERROR\]|\[\d+\/\d+\])/;
const TAG_CLASS={'[*]':'l-ok','[!]':'l-warn','[ERROR]':'l-err'};

function lineEl(text){
 const e=document.createElement('div');
 if(/^\$ /.test(text)){e.className='l-cmd'+(RUN_LINE.test(text)?' l-run':'');e.textContent=text;return e}
 const m=text.match(TAG);
 if(!m){e.textContent=text;return e}
 const end=text.match(END_LINE);
 e.className=end?(end[1]==='0'?'l-ok':'l-err')+' l-end':TAG_CLASS[m[2]]||'l-step';
 e.append(m[1],h('span',{class:'ltag'},m[2]),text.slice(m[0].length));
 return e;
}
function renderLogMeta(){
 if(gapEl)gapEl.textContent=t('log.gap',{n:dropped});
 $('logcount').textContent=lineCount?t('log.lines',{n:(lineCount+dropped).toLocaleString('en-US')}):'';
}
function trimLog(){
 const extra=lineCount-MAX_LINES;
 if(extra<=0)return;
 for(let i=0;i<extra&&logEl.firstChild;i++){
  if(logEl.firstChild===gapEl)gapEl.remove();
  if(logEl.firstChild)logEl.firstChild.remove();
 }
 lineCount=MAX_LINES;dropped+=extra;
 if(!gapEl)gapEl=h('div',{class:'l-gap'});
 logEl.prepend(gapEl);
 renderLogMeta();
}
function ingest(text){
 // 元素可能以换行开头、含多行或缺结尾换行，故按整段拼接后再切行
 const parts=(tail+text.replace(ANSI,'')).split('\n');
 tail=parts.pop();
 if(tailEl){tailEl.remove();tailEl=null;lineCount--}
 const frag=document.createDocumentFragment();
 for(const [i,p] of parts.entries()){
  trackLine(p);
  if(p===''&&(lineCount===0||RUN_LINE.test(parts[i+1]||'')))continue;
  const el=lineEl(p);
  if(PROG.test(p)){
   if(progEl&&progEl.parentNode){progEl.replaceWith(el);progEl=el;continue}
   progEl=el;
  }else progEl=null;
  frag.append(el);lineCount++;
 }
 if(tail){tailEl=lineEl(tail);frag.append(tailEl);lineCount++}
 logEl.append(frag);
 trimLog();
 renderLogMeta();
 if(follow)logEl.scrollTop=logEl.scrollHeight;
 $('jump').hidden=follow;
}
function clearDisplay(){
 logEl.replaceChildren();tailEl=null;progEl=null;gapEl=null;lineCount=0;dropped=0;
 $('logcount').textContent='';follow=true;$('jump').hidden=true;
}
function resetAll(){
 // 服务重启后日志缓冲归零：丢弃本地推导的全部状态
 clearDisplay();off=0;tail='';selected=FLOW[0];replaying=true;
 Object.assign(state,{active:null,sub:null,activeDry:false,stopping:false,last:null,results:{}});
}
function pull(){
 if(inflight)return inflight;
 return inflight=(async()=>{
  try{
   const d=await j('/api/log?off='+off);
   state.online=true;
   if(d.off<off){resetAll();return}
   if(d.lines.length)ingest(d.lines.join(''));
   off=d.off;
   replaying=false;
   // 用后端记录的开始时间，刷新页面后计时仍准
   if(state.active&&d.started)state.startedAt=d.started*1000;
  }catch(e){
   state.online=false;
  }finally{
   inflight=null;
   render();
  }
 })();
}
logEl.addEventListener('scroll',()=>{
 follow=logEl.scrollHeight-logEl.scrollTop-logEl.clientHeight<24;
 $('jump').hidden=follow;
});
$('jump').addEventListener('click',()=>{follow=true;logEl.scrollTop=logEl.scrollHeight;$('jump').hidden=true});
$('logclear').addEventListener('click',clearDisplay);
$('logcopy').addEventListener('click',async()=>{
 const text=[...logEl.children].map(e=>e.textContent).join('\n');
 const btn=$('logcopy');
 try{
  await navigator.clipboard.writeText(text);
  btn.textContent=t('copied');
 }catch(e){
  btn.textContent=t('copyFail');
 }
 setTimeout(()=>{btn.textContent=t('copy')},1200);
});

/* ---------- 目标、feature 与选项 ---------- */
let featToken=0,featDefault=[],targetsLoaded=false,featsReady=false,featMsg='';
let jailbreakMeta={available:false,modes:[],default:'rootless',implemented:[]};
const jailbreakPrefs=Object.create(null);
function setFeatMsg(key){featMsg=key;$('feats').textContent=t(key)}
function featInputs(){return [...document.querySelectorAll('[data-f]')]}
function selectedFeats(){return featInputs().filter(c=>c.checked).map(c=>c.dataset.f)}
function selectedJailbreakMode(){
 return featsReady&&jailbreakMeta.available&&selectedFeats().includes('palera1n')?$('jailbreakmode').value:'';
}
function syncJailbreakMode(){
 const active=!!selectedJailbreakMode();
 $('jailbreaksection').hidden=!active;
 $('jailbreakmode').disabled=!active;
 $('jailbreakwarning').hidden=!active||jailbreakMeta.implemented.includes($('jailbreakmode').value);
}
function refreshFeats(){
 const inputs=featInputs(),sel=selectedFeats(),n=sel.length;
 let changed=false;
 for(const c of inputs){
  const dev=c.checked!==featDefault.includes(c.dataset.f);
  c.closest('.chip').classList.toggle('dev',dev);
  c.nextElementSibling.dataset.dev=t('modified');
  changed=changed||dev;
 }
 const count=inputs.length?n+' / '+inputs.length:'';
 $('featcount').textContent=count;
 $('featcount2').textContent=count;
 $('featlist').textContent=inputs.length?(n?sel.join(' '):t('feat.base'))+(changed?' · '+t('feat.changed'):''):'';
 $('featnone').hidden=!inputs.length||n>0;
 $('featdef').disabled=$('featall').disabled=!inputs.length;
 syncJailbreakMode();renderFlags();
}
function renderFlags(){
 const flags=[];
 const mode=selectedJailbreakMode();
 if(mode)flags.push(['palera1n · '+mode,jailbreakMeta.implemented.includes(mode)?'info':'risk']);
 if($('manual').checked)flags.push(['allow-manual','risk']);
 if($('noid').checked)flags.push([t('flagNoid'),'risk']);
 if(volCfg)flags.push(['s'+volCfg.system+'/s'+volCfg.data+' · '+volCfg.dp,volCfg.dp==='none'?'risk':'info']);
 if($('bootargs').value.trim())flags.push(['boot-args','info']);
 if($('n66ipsw').value.trim())flags.push(['N66 IPSW','info']);
 if($('j96ipsw').value.trim())flags.push(['J96 IPSW','info']);
 $('flags').replaceChildren(...flags.map(([t,c])=>h('span',{class:'flag '+c},t)));
}
async function loadFeats(){
 const t=$('target').value,tok=++featToken,box=$('feats');
 featsReady=false;
 jailbreakMeta={available:false,modes:[],default:'rootless',implemented:[]};
 setFeatMsg('feat.loading');
 refreshFeats();render();
 let d;
 try{d=await j('/api/features?target='+encodeURIComponent(t))}
 catch(e){if(tok===featToken){setFeatMsg('feat.loadFail');refreshFeats()}return}
 if(tok!==featToken)return;
 featDefault=d.sel;featMsg='';
 jailbreakMeta=d.jailbreak||{available:false,modes:[],default:'rootless',implemented:[]};
 const preferred=jailbreakPrefs[t]||jailbreakMeta.default||'rootless';
 $('jailbreakmode').value=jailbreakMeta.modes.includes(preferred)?preferred:'rootless';
 const names=[...new Set([...d.all,...d.sel])].filter(f=>!(jailbreakMeta.available&&f==='rootless')).sort();
 box.replaceChildren(...names.map(f=>{
  const input=h('input',{type:'checkbox','data-f':f,autocomplete:'off',onchange:refreshFeats});
  input.checked=d.sel.includes(f);
  return h('label',{class:'chip'},input,h('span',null,f));
 }));
 if(!names.length)setFeatMsg('feat.none');
 featsReady=true;
 refreshFeats();render();
}
async function loadTargets(){
 const ts=await j('/api/targets');
 $('target').replaceChildren(...ts.map(t=>h('option',null,t)));
 targetsLoaded=true;
 render();
 loadFeats();
 vload();
}
function setAllFeats(fn){for(const c of featInputs())c.checked=fn(c.dataset.f);refreshFeats()}
$('target').addEventListener('change',()=>{loadFeats();vload()});
$('featall').addEventListener('click',()=>setAllFeats(()=>true));
$('featdef').addEventListener('click',()=>setAllFeats(f=>featDefault.includes(f)));
$('dry').addEventListener('change',render);
$('jailbreakmode').addEventListener('change',()=>{jailbreakPrefs[$('target').value]=$('jailbreakmode').value;syncJailbreakMode();renderFlags()});
const drawer=$('drawer');
for(const id of ['fsum','openopts'])$(id).addEventListener('click',()=>drawer.showModal());
$('closeopts').addEventListener('click',()=>drawer.close());
drawer.addEventListener('click',e=>{if(e.target===drawer)drawer.close()});
for(const ev of ['input','change'])drawer.addEventListener(ev,renderFlags);

/* ---------- 阶段 ---------- */
function mkStages(){
 let flowNum=-1;   // init 编号 00
 for(const id in rows)delete rows[id];
 $('chain').replaceChildren();$('combos').replaceChildren();$('queries').replaceChildren();
 for(const id of STAGES){
  const m=META[id]||{},g=m.group||'query';
  if(g==='flow'){
   const pad=h('span',{class:'pad'}),num=String(++flowNum).padStart(2,'0');
   const btn=h('button',{type:'button',class:'node'+(m.tone?' t-'+m.tone:''),onclick:()=>select(id)},pad,
    h('span',{class:'n-num'},num),h('b',{class:'n-name'},title(id)),h('span',{class:'n-id'},id),
    m.tag?tagEl(m):null);
   const li=h('li',null,btn);
   rows[id]={btn,pad,li};
   $('chain').append(li);
  }else if(g==='combo'){
   const pad=h('span',{class:'pad'});
   const btn=h('button',{type:'button',class:'combo',onclick:()=>select(id)},h('span',{class:'combo-id'},m.num),
    h('span',null,h('b',null,label(id)),h('small',null,st(id,'note'))),pad);
   rows[id]={btn,pad};
   $('combos').append(h('li',null,btn));
  }else{
   const btn=h('button',{type:'button',class:'btn sm q',title:st(id,'note'),onclick:()=>run(id)},icon('eye'),label(id));
   rows[id]={btn};
   $('queries').append(btn);
  }
 }
}
function payload(stage){
 return {stage,target:$('target').value,features:selectedFeats(),
  dry:$('dry').checked,manual:$('manual').checked,noid:$('noid').checked,
  bootargs:$('bootargs').value,dp:'',jailbreak_mode:selectedJailbreakMode(),
  n66ipsw:$('n66ipsw').value,j96ipsw:$('j96ipsw').value};
}
function confirmRun(body,meta){
 const edit=meta.sev==='edit',dlg=$('dlg'),items=[[t('dlg.stage'),body.stage],[t('dlg.target'),body.target]];
 dlg.dataset.sev=edit?'edit':'wipe';
 if(FEATURE_STAGES.has(body.stage))items.push(['features',body.features.join(', ')||t('feat.base')]);
 if(body.jailbreak_mode)items.push([t('jbMode'),body.jailbreak_mode]);
 if(VOL_GATED.has(body.stage))items.push([t('spec.vol'),volText()]);
 items.push(['boot-args',body.bootargs.trim()||t('dlg.manifest')]);
 if(body.n66ipsw.trim())items.push(['N66 IPSW',body.n66ipsw.trim()]);
 if(body.j96ipsw.trim())items.push(['J96 IPSW',body.j96ipsw.trim()]);
 if(body.manual)items.push(['allow-manual',t('dlg.on')]);
 $('dlgtitle').textContent=t(edit?'dlg.titleEdit':'dlg.titleWipe',{name:label(body.stage)});
 $('dlgnote').textContent=(body.stage==='all'?t('dlg.clean')+' ':'')+t(edit?'dlg.noteEdit':'dlg.noteWipe',{ready:t(meta.ready)});
 $('dlgrows').replaceChildren(...items.flatMap(([k,v])=>[h('dt',null,k),h('dd',null,v)]));
 $('dlgrows').hidden=false;
 dlg.returnValue='';
 dlg.showModal();
 return new Promise(res=>dlg.addEventListener('close',()=>res(dlg.returnValue==='go'),{once:true}));
}
let noticeState=null;
function renderNotice(){
 $('noticetext').textContent=noticeState?t(noticeState[0],noticeState[1]):'';
 $('notice').hidden=!noticeState;
}
function notice(key,vars){noticeState=key?[key,vars]:null;renderNotice()}
$('noticex').addEventListener('click',()=>notice());
$('run').addEventListener('click',()=>run(selected));
async function run(stage){
 if(isBusy()||(FEATURE_STAGES.has(stage)&&!featsReady))return;
 const body=payload(stage),meta=META[stage]||{};
 if(meta.confirm&&!body.dry&&!(await confirmRun(body,meta)))return;
 // 还没有宗卷设置：先进 ramdisk 读分区，读完自动弹出宗卷设置，确认后再继续这个阶段
 if(VOL_GATED.has(stage)&&!body.dry&&!volCfg){await readPartitionsThen(stage,body);return}
 await launch(stage,body);
}
async function readPartitionsThen(stage,body){
 pendingRun={stage,body};
 notice('notice.volAuto',{stage:label(stage)});
 state.pending=true;render();
 try{
  const r=await postRoot('/api/slots/run',{action:'identify',target:body.target},vt('identify'));
  if(r.reason==='cancelled'){pendingRun=null;notice('notice.pwCancel',{stage:label(stage)})}
  else if(!r.ok){pendingRun=null;notice('notice.volFail')}
 }catch(e){pendingRun=null;notice('notice.req',{msg:e.message})}
 await pull();await pull();
 state.pending=false;render();
}
async function launch(stage,body){
 notice();
 state.pending=true;render();
 if(matchMedia('(max-width:999px)').matches)$('logpanel').scrollIntoView();
 try{
  const r=await postRoot('/api/run',body,label(stage));
  if(r.reason==='cancelled')notice('notice.pwCancel',{stage:label(stage)});
  else if(r.reason==='need-volumes'){volCfg=null;await readPartitionsThen(stage,body);return}
 }catch(e){
  notice('notice.req',{msg:e.message});
 }
 // 起跑那一行已在后端入缓冲；再拉两次（第一次可能复用发请求前的那轮）后才解除 pending
 await pull();await pull();
 state.pending=false;render();
}
$('stop').addEventListener('click',async()=>{
 state.stopping=true;render();
 clearTimeout(stopTimer);
 // 进程可能恰好尚未 spawn，后端不会有回应；超时后允许再点一次
 stopTimer=setTimeout(()=>{state.stopping=false;render()},4000);
 try{await j('/api/stop',{method:'POST'})}
 catch(e){state.stopping=false;notice('notice.stop',{msg:e.message});render()}
 pull();
});

const VT={
"zh-CN":{title:"宗卷设置",gateTitle:"读取设备分区",gate:"宗卷设置以设备上的实际分区为准，识别完成前不给任何默认值。设备进入 ramdisk 后点「识别分区（设备）」（设备在 DFU 时会先自动进入 ramdisk）。",gateDone:"已识别设备分区。分区有变动（格式化、删除、刷机）后请重新识别。",unsupported:"当前目标不支持宗卷安装。",planTitle:"本次安装 · iOS {v}（{target}）",sysLabel:"System 分区",dataLabel:"Data 分区",dpLabel:"Data 加密",newVol:"新建",overwrite12:"覆盖 iOS 12，需要 donor 快照",confirmVol:"确认宗卷设置",confirmAndRun:"确认并继续：{stage}",confirmedTag:"已确认",volSaved:"宗卷设置已确认，现在可以安装。",noteNew:"{list} 会在安装时新建。",noteExisting:"所选分区上的现有内容会在安装时清空。",noteNone:"Data 不加密：iCloud 备份等依赖内容保护的功能不可用。",sameSlice:"System 与 Data 不能是同一个分区。",sub:"分区先声明用途再建立；s3 基带永不格式化；s1、s2 只能格式化后另作他用",back:"← 返回主界面",
 tDevice:"设备",rebind:"改绑",deviceUnbound:"未绑定（连接设备后自动绑定）",rebindConfirm:"改绑会把宗卷记录切换到当前连接的设备，原快照保留。确认？",keepData:"保留 Data 原数据",keepExp:"实验性",keepHint:"实验性：不清空 Data 卷，依赖 iOS 13 对原有 keybag 的兼容，未在设备上验证。",confirmKeep:"安装 iOS {v}（保留 Data 原数据，实验性）？Sys 仍会被清空。",donorOk:"donor 快照可用",donorNo:"donor 快照不可用",
 deviceHint:"设备 ID 是 DFU 阶段读取的 ECID，自动绑定，不再手动填写。快照按它分目录保存在 state/donors/。",
 tSlices:"分区与用途",cSlice:"分区",cPurpose:"用途",cContent:"实际内容",cPerm:"权限",cAction:"操作",
 format:"格式化",clear:"清除用途",delete:"删除",assign:"设定",confirmDelete:"确认删除 {s}？号码将释放，不再复用。",confirmPair:"{s} 属于已装版本：将同时删除该版本的 Sys 与 Data，号码释放且不再复用。继续？",
 tHint:"用途是你的声明；实际内容是分区上物理存在的东西。覆盖原机 12 System 前必须先完成 donor 快照。",
 tVersions:"版本",vVersion:"版本",vStatus:"状态",vSlices:"分区",vAction:"操作",
 plan:"计划",install:"安装",boot:"启动此系统",rebuild:"重建启动包",
 statusNone:"未装",statusOk:"已装",statusStale:"启动包过期",statusBlocked:"不可安装",
 tIdent:"分区识别",identify:"识别分区（设备）",identHint:"需要设备进入 SSH ramdisk（sudo）。System 看 SystemVersion，Data 看安装时写入的标记。",tDonor:"donor 快照",verify:"校验快照",snapshot:"从设备生成快照",donorDeviceHint:"快照需要设备进入 SSH ramdisk（需要 sudo）。",
 tLog:"输出",stop:"停止",running:"已开始，输出见下方控制台。",busy:"有阶段正在运行，等它结束后再试。",cancelled:"已取消：需要管理员密码。",toConsole:"查看控制台",
 wrongSlice:"分区号格式应为 s4 这样",none:"（清除）",noDevice:"先设置设备ID",
 confirmFormat:"确认清空 {s} 的全部内容？此操作不可撤销。",confirmInstall:"确认安装 iOS {v}？将清空对应分区。",
 confirmBoot:"启动会重新发送启动链，设备需进入 DFU。继续？",adopt:"认领",confirmAdopt:"认领 iOS {v}：会检查 Sys 版本，并在 Data 卷写入版本标记。继续？",planBlocked:"阻塞：",ready:"可执行",installed:"已记录为已装",notCommitted:"未提交，仅可建空分区"},
"en":{title:"Volume settings",gateTitle:"Read device partitions",gate:"Volume settings follow the partitions actually on the device; no defaults are offered until they are identified. With the device in ramdisk, click Identify (device). A device in DFU enters ramdisk first.",gateDone:"Device partitions identified. Identify again after formatting, deleting or restoring.",unsupported:"This target does not support slot installs.",planTitle:"This install · iOS {v} ({target})",sysLabel:"System partition",dataLabel:"Data partition",dpLabel:"Data encryption",newVol:"new",overwrite12:"overwrites iOS 12; needs a donor snapshot",confirmVol:"Confirm volume settings",confirmAndRun:"Confirm and continue: {stage}",confirmedTag:"Confirmed",volSaved:"Volume settings confirmed. You can install now.",noteNew:"{list} will be created during install.",noteExisting:"Existing content on the chosen partitions is erased during install.",noteNone:"Data unencrypted: features that need content protection, such as iCloud backup, will not work.",sameSlice:"System and Data must be different partitions.",sub:"Declare each partition's purpose first; s3 baseband is never formatted; s1 and s2 can only be formatted and repurposed",back:"← Back",
 tDevice:"Device",rebind:"Rebind",deviceUnbound:"not bound (bound automatically when the device connects)",rebindConfirm:"Rebinding switches the volume record to the connected device. The existing snapshot is kept. Continue?",keepData:"Keep Data contents",keepExp:"experimental",keepHint:"Experimental: Data is not erased. Depends on iOS 13 accepting the original keybag; not verified on a device.",confirmKeep:"Install iOS {v} keeping Data contents (experimental)? Sys is still erased.",donorOk:"donor snapshot ready",donorNo:"donor snapshot not ready",
 deviceHint:"The device ID is the ECID read in DFU and bound automatically. Snapshots are stored per ID under state/donors/.",
 tSlices:"Partitions and purposes",cSlice:"Slice",cPurpose:"Purpose",cContent:"Actual content",cPerm:"Permissions",cAction:"Actions",
 format:"Format",clear:"Clear purpose",delete:"Delete",assign:"Set",confirmDelete:"Delete {s}? Its number is released and never reused.",confirmPair:"{s} belongs to an installed version: both its Sys and Data will be deleted; numbers are released and never reused. Continue?",
 tHint:"Purpose is your declaration; content is what is physically on the partition. Overwriting the original 12 System needs a donor snapshot first.",
 tVersions:"Versions",vVersion:"Version",vStatus:"Status",vSlices:"Slices",vAction:"Actions",
 plan:"Plan",install:"Install",boot:"Boot this system",rebuild:"Rebuild boot pack",
 statusNone:"not installed",statusOk:"installed",statusStale:"boot pack stale",statusBlocked:"not installable",
 tIdent:"Identify partitions",identify:"Identify (device)",identHint:"Needs the device in SSH ramdisk (sudo). System is read from SystemVersion; Data from the marker written at install.",tDonor:"donor snapshot",verify:"Verify snapshot",snapshot:"Snapshot from device",donorDeviceHint:"Snapshotting needs the device in SSH ramdisk (sudo).",
 tLog:"Output",stop:"Stop",running:"Started. Output is in the console below.",busy:"A stage is running. Try again when it finishes.",cancelled:"Cancelled: the administrator password is required.",toConsole:"Show console",
 wrongSlice:"Slice must look like s4",none:"(clear)",noDevice:"Set device ID first",
 confirmFormat:"Erase all content of {s}? This cannot be undone.",confirmInstall:"Install iOS {v}? The matching partitions will be erased.",
 confirmBoot:"Boot re-sends the boot chain; the device must be in DFU. Continue?",adopt:"Adopt",confirmAdopt:"Adopt iOS {v}: checks the Sys version and writes a version marker on Data. Continue?",planBlocked:"Blocked: ",ready:"ready",installed:"recorded as installed",notCommitted:"not committed; empty volume only"},
"zh-TW":{title:"宗卷設定",gateTitle:"讀取裝置分區",gate:"宗卷設定以裝置上的實際分區為準，識別完成前不提供任何預設值。裝置進入 ramdisk 後點「識別分區（裝置）」（裝置在 DFU 時會先自動進入 ramdisk）。",gateDone:"已識別裝置分區。分區有變動（格式化、刪除、刷機）後請重新識別。",unsupported:"目前目標不支援宗卷安裝。",planTitle:"本次安裝 · iOS {v}（{target}）",sysLabel:"System 分區",dataLabel:"Data 分區",dpLabel:"Data 加密",newVol:"新建",overwrite12:"覆寫 iOS 12，需要 donor 快照",confirmVol:"確認宗卷設定",confirmAndRun:"確認並繼續：{stage}",confirmedTag:"已確認",volSaved:"宗卷設定已確認，現在可以安裝。",noteNew:"{list} 會在安裝時新建。",noteExisting:"所選分區上的現有內容會在安裝時清空。",noteNone:"Data 不加密：iCloud 備份等依賴內容保護的功能無法使用。",sameSlice:"System 與 Data 不能是同一個分區。",sub:"分區先宣告用途再建立；s3 基頻永不格式化；s1、s2 只能格式化後另作他用",back:"← 返回主介面",
 tDevice:"裝置",rebind:"改綁",deviceUnbound:"未綁定（連接裝置後自動綁定）",rebindConfirm:"改綁會把宗卷記錄切換到目前連接的裝置，原快照保留。確認？",keepData:"保留 Data 原資料",keepExp:"實驗性",keepHint:"實驗性：不清空 Data 卷，依賴 iOS 13 對原有 keybag 的相容性，未在裝置上驗證。",confirmKeep:"安裝 iOS {v}（保留 Data 原資料，實驗性）？Sys 仍會被清空。",donorOk:"donor 快照可用",donorNo:"donor 快照不可用",
 deviceHint:"裝置 ID 是 DFU 階段讀取的 ECID，自動綁定。快照依它分目錄存放在 state/donors/。",
 tSlices:"分區與用途",cSlice:"分區",cPurpose:"用途",cContent:"實際內容",cPerm:"權限",cAction:"操作",
 format:"格式化",clear:"清除用途",delete:"刪除",assign:"設定",confirmDelete:"確認刪除 {s}？號碼將釋放，不再復用。",confirmPair:"{s} 屬於已裝版本：將同時刪除該版本的 Sys 與 Data，號碼釋放且不再復用。繼續？",
 tHint:"用途是你的宣告；實際內容是分區上實際存在的東西。覆寫原機 12 System 前必須先完成 donor 快照。",
 tVersions:"版本",vVersion:"版本",vStatus:"狀態",vSlices:"分區",vAction:"操作",
 plan:"計畫",install:"安裝",boot:"啟動此系統",rebuild:"重建啟動包",
 statusNone:"未裝",statusOk:"已裝",statusStale:"啟動包過期",statusBlocked:"不可安裝",
 tIdent:"分區識別",identify:"識別分區（裝置）",identHint:"需要裝置進入 SSH ramdisk（sudo）。System 看 SystemVersion，Data 看安裝時寫入的標記。",tDonor:"donor 快照",verify:"校驗快照",snapshot:"從裝置生成快照",donorDeviceHint:"快照需要裝置進入 SSH ramdisk（需要 sudo）。",
 tLog:"輸出",stop:"停止",running:"已開始，輸出見下方主控台。",busy:"有階段正在執行，等它結束後再試。",cancelled:"已取消：需要管理員密碼。",toConsole:"查看主控台",
 wrongSlice:"分區號格式應為 s4",none:"（清除）",noDevice:"先設定裝置ID",
 confirmFormat:"確認清空 {s} 的全部內容？此操作無法復原。",confirmInstall:"確認安裝 iOS {v}？對應分區將被清空。",
 confirmBoot:"啟動會重新發送啟動鏈，裝置需進入 DFU。繼續？",adopt:"認領",confirmAdopt:"認領 iOS {v}：會檢查 Sys 版本，並在 Data 卷寫入版本標記。繼續？",planBlocked:"阻塞：",ready:"可執行",installed:"已記錄為已裝",notCommitted:"未提交，僅可建空分區"},
"ja":{title:"ボリューム設定",gateTitle:"デバイスのパーティションを読み取る",gate:"ボリューム設定はデバイス上の実際のパーティションに基づきます。識別するまで既定値は表示しません。デバイスを ramdisk にしてから「識別（デバイス）」を押してください（DFU のデバイスは先に ramdisk に入ります）。",gateDone:"デバイスのパーティションを識別済みです。フォーマット・削除・復元の後はもう一度識別してください。",unsupported:"このターゲットはボリュームインストールに対応していません。",planTitle:"今回のインストール · iOS {v}（{target}）",sysLabel:"System パーティション",dataLabel:"Data パーティション",dpLabel:"Data の暗号化",newVol:"新規",overwrite12:"iOS 12 を上書き。donor スナップショットが必要",confirmVol:"ボリューム設定を確定",confirmAndRun:"確定して続行：{stage}",confirmedTag:"確定済み",volSaved:"ボリューム設定を確定しました。インストールできます。",noteNew:"{list} はインストール時に作成されます。",noteExisting:"選んだパーティションの既存の内容はインストール時に消去されます。",noteNone:"Data を暗号化しません：iCloud バックアップなど、コンテンツ保護が必要な機能は使えません。",sameSlice:"System と Data は別のパーティションにしてください。",sub:"パーティションは用途を宣言してから作成します。s3 ベースバンドは決してフォーマットしません。s1・s2 はフォーマットして別用途にのみ使えます",back:"← 戻る",
 tDevice:"デバイス",rebind:"付け替え",deviceUnbound:"未バインド（接続時に自動でバインド）",rebindConfirm:"付け替えると宗卷記録が接続中のデバイスに切り替わります。既存のスナップショットは残ります。続けますか？",keepData:"Data の内容を保持",keepExp:"実験的",keepHint:"実験的：Data を消去しません。元の keybag を iOS 13 が受け入れることに依存し、デバイスでは未検証です。",confirmKeep:"Data の内容を保持して iOS {v} をインストール（実験的）？Sys は引き続き消去されます。",donorOk:"donor スナップショット利用可",donorNo:"donor スナップショット未準備",
 deviceHint:"デバイスIDは DFU で読み取った ECID を自動でバインドします。スナップショットは state/donors/ に保存されます。",
 tSlices:"パーティションと用途",cSlice:"パーティション",cPurpose:"用途",cContent:"実際の内容",cPerm:"権限",cAction:"操作",
 format:"フォーマット",clear:"用途をクリア",delete:"削除",assign:"設定",confirmDelete:"{s} を削除しますか？番号は解放され、再利用されません。",confirmPair:"{s} はインストール済みバージョンに属します。その Sys と Data を両方削除します。番号は解放され再利用されません。続けますか？",
 tHint:"用途はあなたの宣言、実際の内容はパーティション上の実体です。元の 12 System を上書きするには先に donor スナップショットが必要です。",
 tVersions:"バージョン",vVersion:"バージョン",vStatus:"状態",vSlices:"パーティション",vAction:"操作",
 plan:"計画",install:"インストール",boot:"このシステムを起動",rebuild:"ブートパックを再構築",
 statusNone:"未インストール",statusOk:"インストール済み",statusStale:"ブートパック失効",statusBlocked:"インストール不可",
 tIdent:"パーティション識別",identify:"識別（デバイス）",identHint:"デバイスを SSH ramdisk にする必要があります（sudo）。System は SystemVersion、Data はインストール時のマーカーで判定します。",tDonor:"donor スナップショット",verify:"スナップショットを検証",snapshot:"デバイスから作成",donorDeviceHint:"作成にはデバイスを SSH ramdisk にする必要があります（sudo）。",
 tLog:"出力",stop:"停止",running:"開始しました。出力は下のコンソールに表示されます。",busy:"ステージが実行中です。終わってからもう一度試してください。",cancelled:"キャンセルしました：管理者パスワードが必要です。",toConsole:"コンソールを表示",
 wrongSlice:"パーティション番号は s4 の形式で",none:"（クリア）",noDevice:"先にデバイスIDを設定",
 confirmFormat:"{s} の内容をすべて消去しますか？元に戻せません。",confirmInstall:"iOS {v} をインストールしますか？対応するパーティションは消去されます。",
 confirmBoot:"起動はブートチェーンを再送します。デバイスは DFU である必要があります。続けますか？",adopt:"引き取り",confirmAdopt:"iOS {v} を引き取ります：System のバージョンを確認し、Data にマーカーを書き込みます。続けますか？",planBlocked:"ブロック：",ready:"実行可能",installed:"インストール済みとして記録",notCommitted:"未提出。空のボリュームのみ"}
};
/* ---------- 管理员密码（未以 sudo 启动时） ---------- */
function askPassword(what,bad){
 const d=$('pwdlg');
 $('pwnote').textContent=t('pw.note',{what});
 $('pwerr').hidden=!bad;
 $('pwinput').value='';
 d.returnValue='';
 d.showModal();
 $('pwinput').focus();
 return new Promise(res=>d.addEventListener('close',()=>{
  const pw=d.returnValue==='go'?$('pwinput').value:null;
  $('pwinput').value='';
  res(pw);
 },{once:true}));
}
$('pwinput').addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();$('pwdlg').close('go')}});
function post(body){return {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}}
// 需要 root 的请求：本页面会话内记住已验证的管理员密码（只在内存里，刷新即失效），之后自动带上；
// 后端回 need-sudo / bad-password 时才弹窗。
let sudoPw=null;
async function postRoot(url,body,what){
 let pw=sudoPw;
 let r=await j(url,post(pw?{...body,password:pw}:body));
 while(r.reason==='need-sudo'||r.reason==='bad-password'){
  pw=await askPassword(what,r.reason==='bad-password');
  if(pw===null)return {ok:false,reason:'cancelled'};
  r=await j(url,post({...body,password:pw}));
 }
 if(pw&&r.reason!=='bad-password')sudoPw=pw;
 return r;
}
// 通用确认（复用 #dlg）；行列表留空时隐藏
function ask(title,note,sev){
 const dlg=$('dlg');
 dlg.dataset.sev=sev||'wipe';
 $('dlgtitle').textContent=title;
 $('dlgnote').textContent=note||'';
 $('dlgrows').replaceChildren();
 $('dlgrows').hidden=true;
 dlg.returnValue='';
 dlg.showModal();
 return new Promise(res=>dlg.addEventListener('close',()=>res(dlg.returnValue==='go'),{once:true}));
}

/* ---------- 宗卷设置（弹窗） ---------- */
function vt(k,vars){
 const s=(VT[lang]||{})[k]??VT['zh-CN'][k]??k;
 return vars?s.replace(/\{(\w+)\}/g,(m,x)=>x in vars?vars[x]:m):s;
}
const vol=$('vol');
let VS=null;
function applyVol(){for(const e of vol.querySelectorAll('[data-v]'))e.textContent=vt(e.dataset.v)}
function vbtn(text,onclick,disabled,title){
 const b=h('button',{type:'button',class:'btn sm'},text);
 b.disabled=!!disabled;
 if(title)b.title=title;
 b.addEventListener('click',onclick);
 return b;
}
function purposeLabel(p){return p.value+(p.installable?'':' ('+vt('notCommitted')+')')}
function vmsg(text){$('vmsg').textContent=text||''}
async function vload(){
 try{VS=await j('/api/slots?target='+encodeURIComponent($('target').value));volCfg=VS.session.config;renderVolSummary();vrender();render()}
 catch(e){vmsg(t('notice.req',{msg:e.message}))}
}
function vrender(){
 if(!VS)return;
 const sess=VS.session;
 $('vgatenote').textContent=vt(sess.identified?'gateDone':'gate');
 $('vunsupported').hidden=sess.supported;
 $('vdetails').hidden=!sess.identified;
 $('vplanbox').hidden=!(sess.identified&&sess.proposal);
 if(!sess.identified)return;
 $('deviceText').textContent=VS.device_id||vt('deviceUnbound');
 const db=$('donorBadge');
 db.textContent=vt(VS.donor_ready?'donorOk':'donorNo');
 db.className='tag '+(VS.donor_ready?'okt':'edit');
 // 分区与用途
 const rowsS=[];
 for(const k of Object.keys(VS.slices).sort((a,b)=>a-b)){
  const purpose=VS.slices[k],content=VS.content[k],rule=VS.protection[k]||{format:false,delete:false,why:''};
  const sel=h('select',{'aria-label':vt('cPurpose')+' s'+k,autocomplete:'off'},h('option',{value:''},vt('none')),
   ...VS.purposes.map(p=>h('option',{value:p.value},purposeLabel(p))));
  sel.value=purpose||'';
  sel.disabled=k==='3';
  sel.addEventListener('change',()=>vassign('s'+k,sel.value||null));
  const idn=(VS.identified||{})[k];
  let text=content||'—';
  if(idn&&!idn.skipped&&idn.kind)text+='  ·  '+idn.kind+(idn.build?' '+idn.build:'')+(idn.marker?' [marker '+idn.marker+']':'');
  const blockedFormat=!rule.format||(content==='12 Sys'&&!VS.donor_ready);
  rowsS.push(h('tr',null,
   h('td',{class:'mono'},'s'+k),
   h('td',null,h('span',{class:'sel'},sel)),
   h('td',{class:'mono'},text),
   h('td',{class:'v-mut'},(rule.format?'✓ ':'✗ ')+vt('format')+' · '+(rule.delete?'✓ ':'✗ ')+vt('delete')),
   h('td',{class:'vacts'},
    vbtn(vt('format'),()=>vformat(k),blockedFormat,rule.why),
    vbtn(vt('clear'),()=>vassign('s'+k,null),k==='1'||k==='2'||k==='3'),
    vbtn(vt('delete'),()=>vdelete(k),!rule.delete,rule.why))));
 }
 $('slices').replaceChildren(...rowsS);
 $('pairs').textContent=Object.entries(VS.pairs||{}).map(([v,p])=>'iOS '+v+': '+p.note).join('\n');
 const np=$('newPurpose'),keep=np.value;
 np.replaceChildren(...VS.purposes.map(p=>h('option',{value:p.value},purposeLabel(p))));
 if(keep)np.value=keep;
 // 版本
 const rowsV=[];
 for(const v of Object.keys(VS.versions)){
  const info=VS.versions[v],rec=VS.installed[v],boot=VS.boot[v],pair=(VS.pairs||{})[v];
  let status=rec?(boot&&boot.stale?vt('statusStale'):vt('statusOk')):(info.implemented?vt('statusNone'):vt('statusBlocked'));
  if(pair&&pair.status!=='ok'&&rec)status+=' · '+(pair.status==='unknown'?'?':'!')+' '+pair.note;
  if(!info.implemented)status+=' · '+(info.reason||'');
  const cls=rec?(boot&&boot.stale?'v-warn':'v-ok'):'v-mut';
  const keepBox=h('input',{type:'checkbox',id:'keep-'+v,autocomplete:'off'});
  const acts=[
   vbtn(vt('plan'),()=>vplan(v)),
   vbtn(vt('install'),()=>vinstall(v),!info.implemented||!!rec),
   h('label',{class:'vkeep',title:vt('keepHint')},keepBox,h('span',null,vt('keepData')+' ('+vt('keepExp')+')')),
   vbtn(vt('boot'),()=>vact({action:'boot',version:v},[vt('boot')+' · iOS '+v,vt('confirmBoot'),'edit']),!rec),
   vbtn(vt('rebuild'),()=>vact({action:'rebuild',version:v}),!rec)];
  if(!rec)acts.push(vbtn(vt('adopt'),()=>vact({action:'adopt',version:v},[vt('adopt')+' · iOS '+v,vt('confirmAdopt',{v}),'edit']),
   !Object.values(VS.slices).includes(v+' Sys')));
  rowsV.push(h('tr',null,
   h('td',{class:'mono'},'iOS '+v),
   h('td',{class:cls},status),
   h('td',{class:'mono'},rec?'s'+rec.system+' / s'+rec.data:'—'),
   h('td',{class:'vacts'},...acts)));
 }
 $('versions').replaceChildren(...rowsV);
 renderPlanCard();
}
async function vassign(slice,value){
 try{
  const r=await j('/api/slots/assign',post({slice,purpose:value}));
  vmsg(r.ok?'':(r.error||''));
  if(r.ok)vload();
 }catch(e){vmsg(t('notice.req',{msg:e.message}))}
}
function vformat(k){vact({action:'format',slice:'s'+k},[vt('format')+' · s'+k,vt('confirmFormat',{s:'s'+k}),'wipe'])}
function vinstall(v){
 const keep=!!($('keep-'+v)||{}).checked;
 vact({action:'install',version:v,keep},[vt('install')+' · iOS '+v,vt(keep?'confirmKeep':'confirmInstall',{v}),'wipe']);
}
function vdelete(k){
 const pair=Object.values(VS.installed||{}).some(r=>r.system===Number(k)||r.data===Number(k));
 vact({action:'delete',slice:'s'+k,pair},[vt('delete')+' · s'+k,vt(pair?'confirmPair':'confirmDelete',{s:'s'+k}),'wipe']);
}
async function vplan(v){
 const p=$('plan');
 p.hidden=false;
 let r;
 try{r=await j('/api/slots/plan',post({version:v}))}
 catch(e){p.textContent=t('notice.req',{msg:e.message});return}
 if(r.error){p.textContent=r.error;return}
 const lines=[vt('plan')+' · iOS '+v+' · '+(r.status==='ready'?vt('ready'):r.status)];
 if(r.blocked)lines.push(vt('planBlocked')+r.blocked);
 if(r.note)lines.push(r.note);
 if(r.capacity_note)lines.push(r.capacity_note);
 for(const s of r.steps||[])lines.push('  '+s.op+(s.slice!==undefined?' s'+s.slice:'')+(s.purpose?'  ('+s.purpose+')':'')+(s.from?'  from '+s.from:''));
 p.textContent=lines.join('\n');
}
// 宗卷操作也是交给 n56patcher.py 的一个阶段：输出进主控制台，结束后刷新本弹窗
async function vact(body,confirmSpec){
 if(isBusy()){vmsg(vt('busy'));return}
 body={...body,target:$('target').value};
 if(confirmSpec&&!(await ask(...confirmSpec)))return;
 let r;
 try{r=await postRoot('/api/slots/run',body,vt(body.action==='rebind'?'rebind':body.action==='identify'?'identify':body.action==='snapshot'?'snapshot':body.action))}
 catch(e){vmsg(t('notice.req',{msg:e.message}));return}
 if(r.reason==='cancelled'){vmsg(vt('cancelled'));return}
 vmsg(r.ok?vt('running'):r.reason==='busy'?vt('busy'):(r.reason||''));
 await pull();
}
$('btnRebind').addEventListener('click',()=>vact({action:'rebind'},[vt('rebind'),vt('rebindConfirm'),'edit']));
$('btnAssign').addEventListener('click',()=>{
 const s=$('newSlice').value.trim();
 if(!/^s\d+$/.test(s)){vmsg(vt('wrongSlice'));return}
 vassign(s,$('newPurpose').value);
});
$('btnVerify').addEventListener('click',()=>vact({action:'verify'}));
$('btnSnapshot').addEventListener('click',()=>vact({action:'snapshot'}));
$('btnIdentify').addEventListener('click',()=>vact({action:'identify'}));
$('vol2console').addEventListener('click',()=>{vol.close();$('logpanel').scrollIntoView({block:'nearest'})});
$('openvol').addEventListener('click',()=>{drawer.close();openVol()});
// ---- 宗卷优先：本次安装卡片、摘要、打开入口 ----
function volText(){
 return volCfg?t('vol.summary',{v:volCfg.version,sys:volCfg.system,data:volCfg.data,dp:volCfg.dp}):t('vol.none');
}
function renderVolSummary(){$('volsum').textContent=volText();renderFlags()}
function openVol(){vmsg('');if(!vol.open)vol.showModal();vload()}
let planKey='';
// 设备上没有（识别结果里不存在）的号，安装时新建
function isNewSlice(n){return !((VS.identified||{})[n])}
function sliceOptions(p,cfg){
 // 候选：建议值、已确认值 + 设备上识别到的卷（s2 原机 Data、s3 基带除外）
 const ident=VS.identified||{};
 const nums=new Set([...p.new,p.system,p.data,...(cfg?[cfg.system,cfg.data]:[]),...Object.keys(ident).map(Number)]);
 return [...nums].filter(n=>n!==2&&n!==3).sort((a,b)=>a-b).map(n=>{
  const v=ident[n]||{};
  let desc=isNewSlice(n)?vt('newVol'):[v.name,v.kind!==v.name?v.kind:'',v.version?'iOS '+v.version:'',v.marker?'['+v.marker+']':''].filter(Boolean).join(' · ');
  if(n===1)desc+=' · '+vt('overwrite12');
  return [n,'s'+n+' · '+desc];
 });
}
function renderPlanCard(){
 const sess=VS.session,p=sess.proposal,cfg=sess.config;
 if(!p)return;
 $('vplantitle').textContent=vt('planTitle',{v:p.version,target:p.target});
 const key=JSON.stringify([p,cfg,lang]);
 if(key!==planKey){
  planKey=key;
  const opts=sliceOptions(p,cfg);
  for(const [id,val] of [['vsys',cfg?cfg.system:p.system],['vdata',cfg?cfg.data:p.data]]){
   $(id).replaceChildren(...opts.map(([n,label])=>h('option',{value:String(n)},label)));
   $(id).value=String(val);
  }
  $('vdp').replaceChildren(...p.dp_modes.map(m=>h('option',{value:m},m+(m===p.dp_default?' ('+t('dlg.manifest')+')':''))));
  $('vdp').value=cfg?cfg.dp:p.dp;
 }
 updatePlanNote();
}
function updatePlanNote(){
 const p=VS.session.proposal,cfg=VS.session.config;
 const sys=+$('vsys').value,data=+$('vdata').value,dp=$('vdp').value;
 const fresh=[sys,data].filter(isNewSlice);
 const notes=[];
 if(fresh.length)notes.push(vt('noteNew',{list:fresh.map(n=>'s'+n).join('、')}));
 if(fresh.length<2)notes.push(vt('noteExisting'));
 if(dp==='none')notes.push(vt('noteNone'));
 if(sys===data)notes.push(vt('sameSlice'));
 $('vplannote').textContent=notes.join(' ');
 const same=cfg&&cfg.system===sys&&cfg.data===data&&cfg.dp===dp;
 $('vconfirmed').replaceChildren(...(same?[h('span',{class:'tag okt'},vt('confirmedTag'))]:[]));
 $('btnConfirmVol').disabled=sys===data||isBusy();
 $('btnConfirmVol').textContent=pendingRun?vt('confirmAndRun',{stage:label(pendingRun.stage)}):vt('confirmVol');
}
for(const id of ['vsys','vdata','vdp'])$(id).addEventListener('change',updatePlanNote);
$('btnConfirmVol').addEventListener('click',async()=>{
 const body={target:$('target').value,system:+$('vsys').value,data:+$('vdata').value,dp:$('vdp').value};
 try{
  const r=await j('/api/slots/confirm',post(body));
  if(!r.ok){vmsg(r.error||'');return}
  planKey='';
  await vload();
  vmsg(vt('volSaved'));
  if(pendingRun){
   const next=pendingRun;
   pendingRun=null;
   vol.close();
   await launch(next.stage,next.body);
  }
 }catch(e){vmsg(t('notice.req',{msg:e.message}))}
});

$('closevol').addEventListener('click',()=>vol.close());
vol.addEventListener('click',e=>{if(e.target===vol)vol.close()});
vol.addEventListener('close',()=>{
 if(location.hash==='#volumes')history.replaceState(null,'',location.pathname);
 if(pendingRun){notice('notice.volCancel',{stage:label(pendingRun.stage)});pendingRun=null}
});

/* ---------- 启动 ---------- */
async function loop(){
 await pull();
 if(!targetsLoaded&&state.online)loadTargets().catch(()=>{});
 setTimeout(loop,500);
}
$('lang').replaceChildren(...LANGS.map(([v,n])=>{const o=h('option',{value:v},n);return o}));
$('lang').value=lang;
$('lang').addEventListener('change',e=>{
 lang=e.target.value;
 try{localStorage.setItem('n56-lang',lang)}catch(err){}
 applyStatic();mkStages();
 if(featMsg)$('feats').textContent=t(featMsg);
 refreshFeats();renderFlags();renderLogMeta();renderNotice();render();
 applyVol();vrender();renderVolSummary();
});
applyStatic();applyVol();mkStages();render();refreshFeats();loop();
vload();
if(location.hash==='#volumes')openVol();
setInterval(tickTimer,250);
</script></body></html>"""


# ---------------------------------------------------------------- 宗卷设置（主页面里的弹窗）
# 分区用途声明、权限、donor 快照、安装与启动包。所有写操作要么直接改宗卷记录（不碰设备），
# 要么交给 n56patcher.py slots / boot / build 执行，输出进主控制台。



def target_version(target):
    from core import slots
    return next((v for v, t in slots.VERSION_TARGETS.items() if t == target), None)


def volume_proposal(state, target):
    """按目标给出宗卷默认值（只在本次已识别设备分区后调用）。

    宗卷记录里已有该版本的 Sys/Data 优先；其次是设备上识别到的同版本卷（System 按系统版本，
    Data 按安装标记或卷名）；都没有就在设备与记录里最大的分区号之后新建。
    Data 保护模式：记录里选过的优先，否则用目标默认值。
    """
    from core import slots
    from core.context import load_target
    version = target_version(target)
    if version is None:
        return None
    identified = {int(k): v for k, v in state.get("identified", {}).items()}
    sys_value, data_value = slots.purpose(version, "Sys"), slots.purpose(version, "Data")
    system = (slots.slices_of(state, sys_value) or [None])[0]
    data = (slots.slices_of(state, data_value) or [None])[0]
    if system is None:
        system = next((k for k, v in sorted(identified.items()) if k not in (2, 3)
                       and v.get("kind") == "System" and v.get("version") == version), None)
    if data is None:
        data = next((k for k, v in sorted(identified.items()) if k not in (2, 3)
                     and v.get("kind") == "Data" and v.get("marker") == version), None)
    if data is None:
        data = next((k for k, v in sorted(identified.items()) if v.get("name") == f"Data{version}"), None)
    taken = set(identified) | {int(k) for k in state["slices"]} | {int(k) for k in state.get("content", {})}
    taken |= set(state.get("released", [])) | {3}
    following = max(taken) + 1
    new = []
    if system is None:
        system = following
        following += 1
        new.append(system)
    if data is None:
        data = following
        new.append(data)
    default_dp = load_target(target).get("data_protection", "encrypted")
    return {"version": version, "target": target, "system": system, "data": data, "new": new,
            "dp": slots.data_protection_of(state, version, default_dp), "dp_default": default_dp,
            "dp_modes": load_target(target).get("data_protection_modes", ["encrypted"])}


def volume_confirm(body):
    """确认宗卷设置：把 Sys/Data 用途声明到所选分区、记下 Data 保护模式，并解锁写盘阶段。"""
    from core import slots
    from core.slots_cli import STATE_PATH
    target = body.get("target", "")
    version = target_version(target)
    try:
        if not VOL_SESSION["identified"]:
            raise slots.SlotError("先识别设备分区")
        if version is None:
            raise slots.SlotError(f"{target} 不支持宗卷安装")
        system, data = int(body["system"]), int(body["data"])
        if system == data:
            raise slots.SlotError("System 与 Data 不能是同一个分区")
        if 3 in (system, data) or 2 in (system, data):
            raise slots.SlotError("s2（原机 Data）与 s3（基带）不能用作安装目标")
        dp = body.get("dp") or ""

        def apply(state):
            for value, index in ((slots.purpose(version, "Sys"), system), (slots.purpose(version, "Data"), data)):
                for other in slots.slices_of(state, value):
                    if other != index:
                        state = slots.assign(state, other, None)
                if state["slices"].get(str(index)) != value:
                    state = slots.assign(state, index, value)
            return slots.set_data_protection(state, version, dp)
        slots.mutate(STATE_PATH, apply)
    except (slots.SlotError, KeyError, ValueError) as exc:
        return {"ok": False, "error": str(exc)}
    VOL_SESSION["volumes"][target] = {"version": version, "system": system, "data": data, "dp": dp}
    RUNNER.put(f"[*] 宗卷设置：{target} → System s{system}、Data s{data}，Data {dp}\n")
    return {"ok": True}


def slots_state_payload(target=None):
    """宗卷弹窗的状态：只读记录，不访问设备。未识别时不给建议，界面也不显示记录里的默认值。"""
    from core import slots
    from core.slots_cli import STATE_PATH, donor_ready, _donor_dir
    state = slots.load_state(STATE_PATH)
    rules = {k: slots.protection(int(k), v) for k, v in state["slices"].items()}
    identified = {int(k): v for k, v in state.get("identified", {}).items()}
    pairs = {}
    for version in state["installed"]:
        status, note = slots.pair_status(state, version, identified)
        pairs[version] = {"status": status, "note": note}
    return {
        "device_id": state.get("device_id"),
        "donor_ready": donor_ready(state),
        "identified": state.get("identified", {}),
        "pairs": pairs,
        "slices": state["slices"],
        "content": state["content"],
        "protection": rules,
        "purposes": slots.purpose_options(),
        "installed": state["installed"],
        "boot": state["boot"],
        "released": state["released"],
        "versions": {v: {"implemented": info["implemented"], "reason": info.get("reason", "")}
                     for v, info in slots.VERSIONS.items()},
        "session": {
            "identified": VOL_SESSION["identified"],
            "config": VOL_SESSION["volumes"].get(target),
            "proposal": volume_proposal(state, target) if VOL_SESSION["identified"] and target else None,
            "supported": target_version(target) is not None if target else False,
        },
    }


def slots_assign(body):
    from core import slots
    from core.slots_cli import STATE_PATH
    try:
        raw = (body.get("slice") or "").strip()
        if not raw.startswith("s") or not raw[1:].isdigit():
            raise slots.SlotError("分区号格式应为 sN")
        value = body.get("purpose") or None
        slots.mutate(STATE_PATH, lambda st: slots.assign(st, int(raw[1:]), value))
        return {"ok": True}
    except slots.SlotError as exc:
        return {"ok": False, "error": str(exc)}


def slots_plan(body):
    from core import slots
    from core.slots_cli import STATE_PATH, donor_ready
    try:
        state = slots.load_state(STATE_PATH)
        result = slots.plan_install(state, body.get("version", ""), donor_ready(state))
        result["capacity_note"] = "APFS 槽位容量在安装时由设备检查（离线预览不检查）"
        return result
    except slots.SlotError as exc:
        return {"error": str(exc)}


# identify 只读设备、只写本机记录，不需要 root
SLOT_RUN_SUDO = {"snapshot", "format", "install", "delete", "adopt", "rebind"}


def slots_run_args(body):
    from core import slots
    action = body.get("action")
    py = sys.executable
    cli = os.path.join(REPO, "n56patcher.py")
    base = [py, cli, "slots"]
    # 设备操作走当前目标的 ramdisk（端口随目标）；安装、启动、重建按版本自带目标
    if body.get("target") in slots.VERSION_TARGETS.values():
        base += ["--target", body["target"]]
    if action == "snapshot":
        return base + ["snapshot"]
    if action == "verify":
        return base + ["verify"]
    if action == "format":
        return base + ["format", body.get("slice", "")]
    if action == "install":
        return base + ["install", body.get("version", "")] + (["--keep-data"] if body.get("keep") else [])
    if action == "rebind":
        return base + ["rebind-device"]
    if action == "identify":
        return base + ["identify"]
    if action == "adopt":
        return base + ["adopt", body.get("version", "")]
    if action == "delete":
        return base + ["delete", body.get("slice", "")] + (["--pair"] if body.get("pair") else [])
    if action == "boot":
        return base + ["boot", body.get("version", "")]
    if action == "rebuild":
        return base + ["rebuild", body.get("version", "")]
    return None


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body)
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/":
            page = PAGE.replace("%STAGES%", json.dumps(STAGES))
            return self._send(200, page, "text/html")
        if u.path == "/api/targets":
            return self._send(200, list_targets())
        if u.path == "/api/features":
            t = parse_qs(u.query).get("target", ["n56-ios13"])[0]
            sel, allf = target_features(t)
            return self._send(200, {"sel": sel, "all": allf, "jailbreak": jailbreak_metadata(load_target(t))})
        if u.path == "/api/log":
            off = int(parse_qs(u.query).get("off", ["0"])[0])
            lines, total = RUNNER.since(off)
            started = RUNNER.started if RUNNER.running() else 0
            return self._send(200, {"lines": lines, "off": total, "started": started,
                                    "running": RUNNER.running()})
        if u.path == "/volumes":
            # 旧的独立页面：宗卷设置已并入主页面的弹窗
            self.send_response(302)
            self.send_header("Location", "/#volumes")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if u.path == "/api/slots":
            return self._send(200, slots_state_payload(parse_qs(u.query).get("target", [None])[0]))
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        u = urlparse(self.path)
        if u.path == "/api/stop":
            RUNNER.stop()
            return self._send(200, {"ok": True})
        if u.path.startswith("/api/slots"):
            return self._slots_post(u.path)
        if u.path == "/api/run":
            n = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(n) or b"{}")
            config = VOL_SESSION["volumes"].get(body.get("target"))
            if body["stage"] in VOLUME_STAGES and not body.get("dry") and not config:
                return self._send(200, {"ok": False, "reason": "need-volumes"})
            if config and body["stage"] in VOLUME_STAGES | {"build", "boot"}:
                # 宗卷设置给出卷号与 Data 保护模式；build/boot 也带上，工作目录与启动包才一致
                body = {**body, "slot": config["version"], "dp": config["dp"]}
            try:
                args = self._build_args(body)
            except (ValueError, SystemExit) as exc:
                return self._send(400, {"ok": False, "reason": getattr(exc, "message", str(exc))})
            needs_root = body["stage"] in SUDO_STAGES or (body["stage"] in RAMDISK_STAGES and stale_root_proxies())
            if needs_root and not body.get("dry"):
                return self._send(200, start_privileged(args, body, body["stage"]))
            ok = RUNNER.start(args)
            return self._send(200, {"ok": ok})
        return self._send(404, {"error": "not found"})

    def _json_body(self):
        n = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(n) or b"{}")

    def _slots_post(self, path):
        body = self._json_body()
        if path == "/api/slots/assign":
            return self._send(200, slots_assign(body))
        if path == "/api/slots/plan":
            return self._send(200, slots_plan(body))
        if path == "/api/slots/confirm":
            return self._send(200, volume_confirm(body))
        if path == "/api/slots/run":
            action = body.get("action")
            tail = slots_run_args(body)
            if tail is None:
                return self._send(400, {"ok": False, "reason": "unknown-action"})
            on_exit = None
            if action == "identify":
                def on_exit(code):
                    # 识别成功才解锁宗卷设置；重新识别会清掉本次已确认的宗卷（分区可能变了）
                    VOL_SESSION["identified"] = code == 0
                    VOL_SESSION["volumes"].clear()
            if action in SLOT_RUN_SUDO or (action == "identify" and stale_root_proxies()):
                return self._send(200, start_privileged(tail, body, action, on_exit))
            ok = RUNNER.start(tail, on_exit=on_exit)
            return self._send(200, {"ok": ok, "reason": "" if ok else "busy"})
        return self._send(404, {"error": "not found"})

    def _build_args(self, b):
        a = [sys.executable, os.path.join(REPO, "n56patcher.py"), b["stage"],
             "--target", b.get("target", "n56-ios13")]
        if "features" in b and b["stage"] in ("build", "boot", "patch-rootfs", "install", "all", "list"):
            a += ["--features", ",".join(b["features"])]
        if b.get("jailbreak_mode") and b["stage"] in ("build", "boot", "patch-rootfs", "install", "all", "list"):
            target = load_target(b.get("target", "n56-ios13"))
            if "features" in b:
                target["features"] = b["features"]
            configure_jailbreak_mode(target, b["jailbreak_mode"])
            require_backend(target, b["stage"], dry_run=bool(b.get("dry")))
            a += ["--jailbreak-mode", b["jailbreak_mode"]]
        if b.get("dry"):
            a.append("--dry-run")
        if b.get("manual"):
            a.append("--allow-manual")
        if b.get("noid"):
            a.append("--no-identity-check")
        if (b.get("bootargs") or "").strip():
            a += ["--bootargs", b["bootargs"].strip()]
        if b.get("dp"):
            a += ["--data-protection", b["dp"]]
        if b.get("slot"):
            a += ["--slot", b["slot"]]
        if (b.get("n66ipsw") or "").strip():
            a += ["--n66-ipsw", b["n66ipsw"].strip()]
        if (b.get("j96ipsw") or "").strip():
            a += ["--j96-ipsw", b["j96ipsw"].strip()]
        return a


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8756)
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    url = f"http://{args.host}:{args.port}"
    print(f"n56-patcher GUI: {url}  (Ctrl-C 退出)")
    try:
        import webbrowser
        webbrowser.open(url)
    except Exception:
        pass
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n退出。")


if __name__ == "__main__":
    main()
