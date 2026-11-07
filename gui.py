#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""n56-patcher 本地网页界面（标准库 http.server，零依赖）。

本机 Python 可能不带 tkinter，故用浏览器界面：选目标、勾 feature、切选项、点阶段，
日志实时回显。每个阶段以 subprocess 跑 n56patcher.py，输出流式送到页面。

运行：python3 gui.py            # 默认 http://127.0.0.1:8756
      sudo python3 gui.py       # 需要跑 rootfs/install/all（写盘）时用 sudo 起
      python3 gui.py --port 9000
仅监听本地回环，不对外。
"""
import argparse
import json
import os
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

REPO = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, REPO)

from core.context import load_target, TARGETS_DIR
from core import patch as patchmod

SUDO_STAGES = {"rootfs", "install", "all"}
STAGES = ["ramdisk", "extract-im4m", "volumes", "rootfs",
          "patch-rootfs", "build", "boot", "all", "status", "list"]


def list_targets():
    out = [fn[:-3].replace("_", "-") for fn in sorted(os.listdir(TARGETS_DIR))
           if fn.endswith(".py") and not fn.startswith("_")]
    return out or ["n56-ios13"]


def target_features(name):
    try:
        t = load_target(name)
    except SystemExit:
        return [], []
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

    def start(self, args):
        if self.running():
            self.put("[!] 有阶段正在运行。\n")
            return False
        self.started = time.time()
        self.put("\n$ " + " ".join(args) + "\n")
        threading.Thread(target=self._spawn, args=(args,), daemon=True).start()
        return True

    def _spawn(self, args):
        try:
            self.proc = subprocess.Popen(args, cwd=REPO, stdout=subprocess.PIPE,
                                         stderr=subprocess.STDOUT, bufsize=1, text=True)
        except Exception as e:
            self.put(f"[ERROR] 启动失败：{e}\n")
            return
        for line in self.proc.stdout:
            self.put(line)
        self.proc.wait()
        self.put(f"[*] 阶段结束，退出码 {self.proc.returncode}\n")

    def stop(self):
        if self.running():
            self.proc.terminate()
            self.put("[!] 已请求停止。\n")


RUNNER = Runner()

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
select,input[type=text]{width:100%;height:32px;padding:0 10px;background:var(--ink);
 border:1px solid var(--line2);border-radius:2px;transition:border-color .12s}
select{appearance:none;-webkit-appearance:none;padding-right:28px;cursor:pointer;font-family:var(--mono);font-size:12.5px}
select:hover,input[type=text]:hover{border-color:var(--mut)}
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
.chain{display:grid;grid-template-columns:repeat(7,minmax(0,1fr));margin-top:8px;
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
 select,input[type=text]{height:40px;font-size:16px}
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
  <section class="dws" aria-labelledby="h-feat">
   <div class="ph"><h2 id="h-feat">Feature</h2><small id="featcount2"></small>
    <span class="end"><button type="button" class="btn sm" id="featdef" data-i18n="restore"></button><button type="button" class="btn sm" id="featall" data-i18n="selectAll"></button></span></div>
   <div class="chips" id="feats"></div>
   <p class="hint" id="featnone" data-i18n="featNone" hidden></p>
   <p class="hint" data-i18n="featHint"></p>
  </section>
  <section class="dws" aria-labelledby="h-risk">
   <div class="ph"><h2 id="h-risk" data-i18n="risk"></h2></div>
   <label class="optrow"><span><b>allow-manual</b><em data-i18n="manualDesc"></em></span><input type="checkbox" role="switch" id="manual" autocomplete="off"><span class="sw"></span></label>
   <label class="optrow"><span><b data-i18n="noid"></b><em data-i18n="noidDesc"></em></span><input type="checkbox" role="switch" id="noid" autocomplete="off"><span class="sw"></span></label>
  </section>
  <section class="dws" aria-labelledby="h-input">
   <div class="ph"><h2 id="h-input" data-i18n="input"></h2></div>
   <label class="field"><span data-i18n="dp"></span><span class="sel"><select id="dp" autocomplete="off">
    <option value="" data-i18n="dpDefaultEnc"></option><option value="encrypted">encrypted</option><option value="none">none</option></select></span></label>
   <label class="field"><span>N66 13.7 IPSW</span><input type="text" id="n66ipsw" data-i18n-attr="placeholder:ipswPh" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false"></label>
   <label class="field"><span>J96 13.7 IPSW</span><input type="text" id="j96ipsw" data-i18n-attr="placeholder:ipswPh" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false"></label>
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

<script>
const STAGES=%STAGES%;
const I18N={
 "zh-CN":{
  sub:"iPhone 6 Plus · 第二系统 iOS 13.7",lang:"语言",target:"目标",stop:"停止",stopping:"停止中…",
  chain:"启动链",chainHint:"节点状态只记录本次服务运行期间的结果，不代表设备实际状态",stepAria:"当前步骤",closeNotice:"关闭提示",
  combos:"一键组合",console:"控制台",copy:"复制",copied:"已复制",copyFail:"复制失败",clear:"清屏",clearTitle:"只清空显示，不影响后端缓冲",jump:"回到底部",logEmpty:"尚无输出。选中阶段并点击执行后，日志会显示在这里。",
  openOpts:"打开选项",options:"选项",close:"关闭",restore:"恢复默认",selectAll:"全选",featNone:"未选 feature：仅构建基础层。",featHint:"功能选择用于构建、自动构建启动和安装阶段，真实依赖自动补齐。",
  risk:"放宽检查",manualDesc:"执行标记为 manual 的 patch",noid:"不校验设备身份",noidDesc:"boot 时跳过身份检查",input:"输入与覆盖",dp:"Data 加密",dpDefaultEnc:"清单默认（encrypted）",ipswPh:"已导入 DMG 时可留空",bootargs:"boot-args 覆盖",bootargsPh:"留空用清单默认",
  cancel:"取消",confirm:"确认执行",modified:"改",
  "tag.sudo":"写盘 · sudo","tag.edit":"写设备","tag.must":"刷机后必做","tag.opt":"可选",
  "result.run":"运行中","result.ok":"成功","result.dry":"演练通过（未实际执行）","result.fail":"失败","result.stop":"已停止","result.none":"本次未运行",
  "spec.effect":"影响","spec.need":"前置","spec.perm":"权限","spec.result":"结果",permText:"用 sudo python3 gui.py 启动本界面（dry-run 不需要）",
  "btn.running":"运行中 · {stage}","btn.offline":"本地服务断开","btn.loading":"加载 feature…","btn.dry":"演练 {name}","btn.run":"执行 {name}",
  "pill.idle":"空闲","pill.off":"与本地服务断开，重连中…","pill.dryRun":"演练中 · {stage}","pill.run":"运行中 · {stage}","pill.starting":"正在启动…","pill.stage":"阶段","pill.dryOk":"演练通过","pill.ok":"完成","pill.stop":"已停止","pill.fail":"失败","pill.end":"{status} · {stage} · 退出码 {code}",
  "log.gap":"… 更早的 {n} 行已从显示中移除","log.lines":"{n} 行",
  "feat.base":"仅基础层","feat.changed":"已改","feat.loading":"加载中…","feat.loadFail":"feature 加载失败。","feat.none":"该目标没有可选 feature。",flagNoid:"跳过身份校验",
  "dlg.stage":"阶段","dlg.target":"目标","dlg.manifest":"清单默认","dlg.on":"开","dlg.titleEdit":"确认写设备：{name}","dlg.titleWipe":"确认写盘：{name}",
  "dlg.noteEdit":"此阶段会改动设备（新建/修改卷或向 SystemB 写入文件、改卷 role）。确认设备{ready}。","dlg.noteWipe":"此阶段会写入设备存储（rootfs 全量流写会先清空目标卷）。确认设备{ready}，运行期间不要断开连接。",
  "ready.ramdisk":"已进 ramdisk","ready.dfu":"处于 DFU",
  "notice.sudo":"当前未以 root 启动，{stage} 未执行（写盘需 root；dry-run 不受此限）。请退出后用 sudo python3 gui.py 重新启动本界面。","notice.req":"请求失败：{msg}","notice.stop":"停止请求失败：{msg}",
  s:{
   ramdisk:{short:"进 ramdisk",note:"DFU → gaster → SSH ramdisk 就绪",effect:"引导 SSH ramdisk，不写设备存储",need:"设备处于 DFU"},
   "extract-im4m":{short:"重提 IM4M",label:"重提 IM4M（刷机后）",note:"读 NOR 重提本机 IM4M。刷机后必须执行，否则组件可能无法通过校验。",effect:"只读设备，写入本地 state/IM4M.bin",need:"ramdisk 已就绪"},
   volumes:{short:"建分区 s4/s5",note:"在容器内新建 s4 SystemB / s5 DataB（role 0）。",effect:"写设备：新建卷",need:"ramdisk 已就绪"},
   rootfs:{short:"写 rootfs",note:"清空目标卷后把 iOS13 rootfs 流式写入 s4，约 25 分钟。",effect:"写设备：清空目标卷后全量写入",need:"ramdisk 已就绪"},
   "patch-rootfs":{short:"施加 patch",label:"施加 rootfs patch",note:"向 SystemB 写入 overlay，完成收尾并改卷 role。",effect:"写设备：写入文件、改卷 role",need:"ramdisk 已就绪"},
   build:{short:"构建启动镜像",note:"iBSS / iBEC / DT / TC / KC → img4",effect:"只写本地 build 目录",need:"首次构建需设备处于 DFU（解密 iBSS、iBEC）"},
   boot:{short:"启动 iOS13",note:"经 DFU 发送启动链，缺组件时先 build。",effect:"向设备发送启动链，不写设备存储",need:"设备处于 DFU"},
   all:{short:"端到端",note:"缺 iBSS/iBEC 时先解密，再 ramdisk + extract-im4m + volumes + rootfs + patch-rootfs + build + boot",effect:"写设备：清空目标卷后全量写入",need:"设备处于 DFU（流程内自动进 ramdisk）"},
   status:{short:"查看卷 role",note:"各卷 apfs_role · 需 ramdisk"},
   list:{short:"列出选挂",note:"当前选挂的 patch"}
  }
 },
 "en":{
  sub:"iPhone 6 Plus · Second system iOS 13.7",lang:"Language",target:"Target",stop:"Stop",stopping:"Stopping…",
  chain:"Boot chain",chainHint:"Node status only reflects results from this server session, not the actual device state",stepAria:"Current step",closeNotice:"Dismiss notice",
  combos:"Combos",console:"Console",copy:"Copy",copied:"Copied",copyFail:"Copy failed",clear:"Clear",clearTitle:"Clears the display only, not the server buffer",jump:"Back to bottom",logEmpty:"No output yet. Select a stage and run it to see logs here.",
  openOpts:"Open options",options:"Options",close:"Close",restore:"Restore defaults",selectAll:"Select all",featNone:"No features selected: only the base layer is built.",featHint:"Feature selection applies to the build, auto-build boot and install stages. Real dependencies are added automatically.",
  risk:"Relaxed checks",manualDesc:"Run patches marked as manual",noid:"Skip device identity check",noidDesc:"Skips the identity check during boot",input:"Inputs and overrides",dp:"Data encryption",dpDefaultEnc:"Manifest default (encrypted)",ipswPh:"Optional if the DMG is already imported",bootargs:"boot-args override",bootargsPh:"Leave empty for the manifest default",
  cancel:"Cancel",confirm:"Run",modified:"edited",
  "tag.sudo":"Writes · sudo","tag.edit":"Writes device","tag.must":"Required after restore","tag.opt":"Optional",
  "result.run":"Running","result.ok":"Succeeded","result.dry":"Dry run passed (nothing executed)","result.fail":"Failed","result.stop":"Stopped","result.none":"Not run this session",
  "spec.effect":"Effect","spec.need":"Requires","spec.perm":"Permission","spec.result":"Result",permText:"Start this UI with sudo python3 gui.py (not needed for dry-run)",
  "btn.running":"Running · {stage}","btn.offline":"Local server disconnected","btn.loading":"Loading features…","btn.dry":"Dry run: {name}","btn.run":"Run: {name}",
  "pill.idle":"Idle","pill.off":"Disconnected from local server, reconnecting…","pill.dryRun":"Dry run · {stage}","pill.run":"Running · {stage}","pill.starting":"Starting…","pill.stage":"Stage","pill.dryOk":"Dry run passed","pill.ok":"Done","pill.stop":"Stopped","pill.fail":"Failed","pill.end":"{status} · {stage} · exit code {code}",
  "log.gap":"… {n} earlier lines removed from the display","log.lines":"{n} lines",
  "feat.base":"Base layer only","feat.changed":"edited","feat.loading":"Loading…","feat.loadFail":"Failed to load features.","feat.none":"This target has no optional features.",flagNoid:"Identity check skipped",
  "dlg.stage":"Stage","dlg.target":"Target","dlg.manifest":"Manifest default","dlg.on":"On","dlg.titleEdit":"Confirm device write: {name}","dlg.titleWipe":"Confirm disk write: {name}",
  "dlg.noteEdit":"This stage changes the device: it creates or modifies volumes, or writes files to SystemB and changes volume roles. Make sure the device {ready}.","dlg.noteWipe":"This stage writes to device storage, and the full rootfs stream wipes the target volume first. Make sure the device {ready}, and stay connected while it runs.",
  "ready.ramdisk":"is in ramdisk","ready.dfu":"is in DFU",
  "notice.sudo":"This server is not running as root, so {stage} did not run. Disk writes need root; dry-run does not. Quit and restart this UI with sudo python3 gui.py.","notice.req":"Request failed: {msg}","notice.stop":"Stop request failed: {msg}",
  s:{
   ramdisk:{short:"Enter ramdisk",note:"DFU → gaster → SSH ramdisk ready",effect:"Boots the SSH ramdisk without writing device storage",need:"Device in DFU"},
   "extract-im4m":{short:"Re-extract IM4M",label:"Re-extract IM4M (after restore)",note:"Reads NOR to re-extract this device's IM4M. Required after a restore, or components may fail validation.",effect:"Reads the device and writes local state/IM4M.bin",need:"Ramdisk ready"},
   volumes:{short:"Create s4/s5",label:"Create volumes s4/s5",note:"Creates s4 SystemB and s5 DataB (role 0) in the container.",effect:"Writes device: creates volumes",need:"Ramdisk ready"},
   rootfs:{short:"Write rootfs",note:"Wipes the target volume, then streams the iOS 13 rootfs to s4. Takes about 25 minutes.",effect:"Writes device: wipes the target volume, then writes everything",need:"Ramdisk ready"},
   "patch-rootfs":{short:"Apply patches",label:"Apply rootfs patches",note:"Writes overlays to SystemB, finishes setup and changes volume roles.",effect:"Writes device: writes files and changes volume roles",need:"Ramdisk ready"},
   build:{short:"Build images",label:"Build boot images",note:"iBSS / iBEC / DT / TC / KC → img4",effect:"Writes the local build directory only",need:"First build needs the device in DFU (to decrypt iBSS and iBEC)"},
   boot:{short:"Boot iOS 13",note:"Sends the boot chain through DFU, building first if components are missing.",effect:"Sends the boot chain without writing device storage",need:"Device in DFU"},
   all:{short:"End to end",note:"Decrypts iBSS/iBEC if missing, then ramdisk + extract-im4m + volumes + rootfs + patch-rootfs + build + boot",effect:"Writes device: wipes the target volume, then writes everything",need:"Device in DFU (enters ramdisk automatically)"},
   status:{short:"Volume roles",note:"apfs_role of each volume · needs ramdisk"},
   list:{short:"List selection",note:"Currently selected patches"}
  }
 },
 "zh-TW":{
  sub:"iPhone 6 Plus · 第二系統 iOS 13.7",lang:"語言",target:"目標",stop:"停止",stopping:"停止中…",
  chain:"啟動鏈",chainHint:"節點狀態只記錄本次服務執行期間的結果，不代表裝置實際狀態",stepAria:"目前步驟",closeNotice:"關閉提示",
  combos:"一鍵組合",console:"主控台",copy:"複製",copied:"已複製",copyFail:"複製失敗",clear:"清除",clearTitle:"只清除顯示，不影響後端緩衝",jump:"回到底部",logEmpty:"尚無輸出。選取階段並點擊執行後，日誌會顯示在這裡。",
  openOpts:"開啟選項",options:"選項",close:"關閉",restore:"恢復預設",selectAll:"全選",featNone:"未選 feature：僅建置基礎層。",featHint:"功能選擇用於建置、自動建置啟動和安裝階段，實際相依項目自動補齊。",
  risk:"放寬檢查",manualDesc:"執行標記為 manual 的 patch",noid:"不驗證裝置身分",noidDesc:"boot 時略過身分檢查",input:"輸入與覆蓋",dp:"Data 加密",dpDefaultEnc:"清單預設（encrypted）",ipswPh:"已匯入 DMG 時可留空",bootargs:"boot-args 覆蓋",bootargsPh:"留空使用清單預設",
  cancel:"取消",confirm:"確認執行",modified:"改",
  "tag.sudo":"寫入磁碟 · sudo","tag.edit":"寫入裝置","tag.must":"刷機後必做","tag.opt":"選用",
  "result.run":"執行中","result.ok":"成功","result.dry":"演練通過（未實際執行）","result.fail":"失敗","result.stop":"已停止","result.none":"本次未執行",
  "spec.effect":"影響","spec.need":"前置","spec.perm":"權限","spec.result":"結果",permText:"用 sudo python3 gui.py 啟動本介面（dry-run 不需要）",
  "btn.running":"執行中 · {stage}","btn.offline":"本機服務已中斷","btn.loading":"載入 feature…","btn.dry":"演練 {name}","btn.run":"執行 {name}",
  "pill.idle":"閒置","pill.off":"與本機服務中斷，重新連線中…","pill.dryRun":"演練中 · {stage}","pill.run":"執行中 · {stage}","pill.starting":"正在啟動…","pill.stage":"階段","pill.dryOk":"演練通過","pill.ok":"完成","pill.stop":"已停止","pill.fail":"失敗","pill.end":"{status} · {stage} · 結束代碼 {code}",
  "log.gap":"… 更早的 {n} 行已從顯示中移除","log.lines":"{n} 行",
  "feat.base":"僅基礎層","feat.changed":"已改","feat.loading":"載入中…","feat.loadFail":"feature 載入失敗。","feat.none":"此目標沒有可選 feature。",flagNoid:"略過身分驗證",
  "dlg.stage":"階段","dlg.target":"目標","dlg.manifest":"清單預設","dlg.on":"開","dlg.titleEdit":"確認寫入裝置：{name}","dlg.titleWipe":"確認寫入磁碟：{name}",
  "dlg.noteEdit":"此階段會變更裝置（新建/修改磁碟區或向 SystemB 寫入檔案、變更磁碟區 role）。請確認裝置{ready}。","dlg.noteWipe":"此階段會寫入裝置儲存空間（rootfs 全量串流寫入會先清空目標磁碟區）。請確認裝置{ready}，執行期間不要中斷連線。",
  "ready.ramdisk":"已進入 ramdisk","ready.dfu":"處於 DFU",
  "notice.sudo":"目前未以 root 啟動，{stage} 未執行（寫入磁碟需要 root；dry-run 不受此限）。請結束後用 sudo python3 gui.py 重新啟動本介面。","notice.req":"請求失敗：{msg}","notice.stop":"停止請求失敗：{msg}",
  s:{
   ramdisk:{short:"進入 ramdisk",note:"DFU → gaster → SSH ramdisk 就緒",effect:"引導 SSH ramdisk，不寫入裝置儲存空間",need:"裝置處於 DFU"},
   "extract-im4m":{short:"重新提取 IM4M",label:"重新提取 IM4M（刷機後）",note:"讀取 NOR 重新提取本機 IM4M。刷機後必須執行，否則元件可能無法通過驗證。",effect:"唯讀裝置，寫入本機 state/IM4M.bin",need:"ramdisk 已就緒"},
   volumes:{short:"建立 s4/s5",label:"建立磁碟區 s4/s5",note:"在容器內新建 s4 SystemB / s5 DataB（role 0）。",effect:"寫入裝置：新建磁碟區",need:"ramdisk 已就緒"},
   rootfs:{short:"寫入 rootfs",note:"清空目標磁碟區後把 iOS13 rootfs 串流寫入 s4，約 25 分鐘。",effect:"寫入裝置：清空目標磁碟區後全量寫入",need:"ramdisk 已就緒"},
   "patch-rootfs":{short:"套用 patch",label:"套用 rootfs patch",note:"向 SystemB 寫入 overlay，完成收尾並變更磁碟區 role。",effect:"寫入裝置：寫入檔案、變更磁碟區 role",need:"ramdisk 已就緒"},
   build:{short:"建置啟動映像",note:"iBSS / iBEC / DT / TC / KC → img4",effect:"只寫入本機 build 目錄",need:"首次建置需裝置處於 DFU（解密 iBSS、iBEC）"},
   boot:{short:"啟動 iOS13",note:"經 DFU 傳送啟動鏈，缺元件時先 build。",effect:"向裝置傳送啟動鏈，不寫入裝置儲存空間",need:"裝置處於 DFU"},
   all:{short:"端到端",note:"缺 iBSS/iBEC 時先解密，再 ramdisk + extract-im4m + volumes + rootfs + patch-rootfs + build + boot",effect:"寫入裝置：清空目標磁碟區後全量寫入",need:"裝置處於 DFU（流程內自動進入 ramdisk）"},
   status:{short:"查看磁碟區 role",note:"各磁碟區 apfs_role · 需要 ramdisk"},
   list:{short:"列出選取項目",note:"目前選取的 patch"}
  }
 },
 "ja":{
  sub:"iPhone 6 Plus · セカンドシステム iOS 13.7",lang:"言語",target:"ターゲット",stop:"停止",stopping:"停止中…",
  chain:"ブートチェーン",chainHint:"ノードの状態はこのサーバー実行中の結果のみで、デバイスの実際の状態ではありません",stepAria:"現在のステップ",closeNotice:"通知を閉じる",
  combos:"ワンクリック",console:"コンソール",copy:"コピー",copied:"コピーしました",copyFail:"コピー失敗",clear:"クリア",clearTitle:"表示のみクリアし、サーバーのバッファには影響しません",jump:"一番下へ",logEmpty:"出力はまだありません。ステージを選択して実行すると、ここにログが表示されます。",
  openOpts:"オプションを開く",options:"オプション",close:"閉じる",restore:"デフォルトに戻す",selectAll:"すべて選択",featNone:"feature 未選択：ベースレイヤーのみビルドします。",featHint:"機能の選択はビルド、自動ビルド起動、インストールの各ステージに適用され、依存関係は自動で補完されます。",
  risk:"チェックの緩和",manualDesc:"manual と指定された patch を実行",noid:"デバイス ID を検証しない",noidDesc:"boot 時に ID チェックをスキップ",input:"入力と上書き",dp:"Data 暗号化",dpDefaultEnc:"マニフェスト既定（encrypted）",ipswPh:"DMG をインポート済みなら空欄可",bootargs:"boot-args の上書き",bootargsPh:"空欄でマニフェスト既定を使用",
  cancel:"キャンセル",confirm:"実行する",modified:"変更",
  "tag.sudo":"書き込み · sudo","tag.edit":"デバイス書き込み","tag.must":"復元後に必須","tag.opt":"任意",
  "result.run":"実行中","result.ok":"成功","result.dry":"ドライラン成功（実行なし）","result.fail":"失敗","result.stop":"停止しました","result.none":"今回は未実行",
  "spec.effect":"影響","spec.need":"前提","spec.perm":"権限","spec.result":"結果",permText:"sudo python3 gui.py でこの画面を起動（dry-run では不要）",
  "btn.running":"実行中 · {stage}","btn.offline":"ローカルサーバーから切断","btn.loading":"feature を読み込み中…","btn.dry":"ドライラン：{name}","btn.run":"実行：{name}",
  "pill.idle":"待機中","pill.off":"ローカルサーバーから切断、再接続中…","pill.dryRun":"ドライラン中 · {stage}","pill.run":"実行中 · {stage}","pill.starting":"起動中…","pill.stage":"ステージ","pill.dryOk":"ドライラン成功","pill.ok":"完了","pill.stop":"停止しました","pill.fail":"失敗","pill.end":"{status} · {stage} · 終了コード {code}",
  "log.gap":"… 以前の {n} 行を表示から削除しました","log.lines":"{n} 行",
  "feat.base":"ベースレイヤーのみ","feat.changed":"変更あり","feat.loading":"読み込み中…","feat.loadFail":"feature の読み込みに失敗しました。","feat.none":"このターゲットに選択可能な feature はありません。",flagNoid:"ID 検証をスキップ",
  "dlg.stage":"ステージ","dlg.target":"ターゲット","dlg.manifest":"マニフェスト既定","dlg.on":"オン","dlg.titleEdit":"デバイス書き込みの確認：{name}","dlg.titleWipe":"ディスク書き込みの確認：{name}",
  "dlg.noteEdit":"このステージはデバイスを変更します（ボリュームの作成・変更、SystemB へのファイル書き込み、ボリューム role の変更）。デバイスが{ready}ことを確認してください。","dlg.noteWipe":"このステージはデバイスのストレージに書き込みます（rootfs の全量書き込みでは先にターゲットボリュームを消去します）。デバイスが{ready}ことを確認し、実行中は接続を切らないでください。",
  "ready.ramdisk":"ramdisk に入っている","ready.dfu":"DFU 状態である",
  "notice.sudo":"root で起動していないため、{stage} は実行されませんでした（書き込みには root が必要です。dry-run は対象外です）。終了して sudo python3 gui.py で再起動してください。","notice.req":"リクエスト失敗：{msg}","notice.stop":"停止リクエスト失敗：{msg}",
  s:{
   ramdisk:{short:"ramdisk に入る",note:"DFU → gaster → SSH ramdisk 準備完了",effect:"SSH ramdisk を起動。デバイスのストレージには書き込みません",need:"デバイスが DFU 状態"},
   "extract-im4m":{short:"IM4M を再抽出",label:"IM4M を再抽出（復元後）",note:"NOR を読み取り、このデバイスの IM4M を再抽出します。復元後は必須で、実行しないとコンポーネントが検証を通らない場合があります。",effect:"デバイスは読み取りのみ。ローカルの state/IM4M.bin に書き込みます",need:"ramdisk 準備完了"},
   volumes:{short:"s4/s5 を作成",label:"ボリューム s4/s5 を作成",note:"コンテナ内に s4 SystemB / s5 DataB（role 0）を作成します。",effect:"デバイス書き込み：ボリュームを作成",need:"ramdisk 準備完了"},
   rootfs:{short:"rootfs を書き込み",note:"ターゲットボリュームを消去し、iOS 13 の rootfs を s4 にストリーム書き込みします。約 25 分かかります。",effect:"デバイス書き込み：ターゲットボリュームを消去して全量書き込み",need:"ramdisk 準備完了"},
   "patch-rootfs":{short:"patch を適用",label:"rootfs patch を適用",note:"SystemB に overlay を書き込み、仕上げを行ってボリューム role を変更します。",effect:"デバイス書き込み：ファイル書き込み、ボリューム role の変更",need:"ramdisk 準備完了"},
   build:{short:"イメージをビルド",label:"ブートイメージをビルド",note:"iBSS / iBEC / DT / TC / KC → img4",effect:"ローカルの build ディレクトリのみ書き込み",need:"初回ビルドではデバイスを DFU にする必要があります（iBSS、iBEC の復号）"},
   boot:{short:"iOS 13 を起動",note:"DFU 経由でブートチェーンを送信します。コンポーネントが不足していれば先に build します。",effect:"ブートチェーンを送信。デバイスのストレージには書き込みません",need:"デバイスが DFU 状態"},
   all:{short:"エンドツーエンド",note:"iBSS/iBEC がなければ先に復号し、ramdisk + extract-im4m + volumes + rootfs + patch-rootfs + build + boot を実行",effect:"デバイス書き込み：ターゲットボリュームを消去して全量書き込み",need:"デバイスが DFU 状態（フロー内で自動的に ramdisk に入ります）"},
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
 ramdisk:{group:'flow'},
 'extract-im4m':{group:'flow',tone:'must',tag:'must'},
 volumes:{group:'flow',tone:'edit',confirm:1,sev:'edit',tag:'edit',ready:'ready.ramdisk'},
 rootfs:{group:'flow',tone:'danger',confirm:1,sev:'wipe',sudo:1,tag:'sudo',ready:'ready.ramdisk'},
 'patch-rootfs':{group:'flow',tone:'edit',confirm:1,sev:'edit',tag:'edit',ready:'ready.ramdisk'},
 build:{group:'flow'},
 boot:{group:'flow'},
 all:{group:'combo',num:'A',tone:'danger',confirm:1,sev:'wipe',sudo:1,tag:'sudo',members:['ramdisk','extract-im4m','volumes','rootfs','patch-rootfs','build','boot'],ready:'ready.dfu'},
 status:{group:'query'},
 list:{group:'query'}
};
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
 state.sub=id;state.results[id]='run';
}
// 端到端运行时带上当前子阶段和进度，其他阶段只显示 ID
function activeName(){
 if(!state.sub)return state.active;
 const ms=META[state.active].members;
 return label(state.active)+' · '+title(state.sub)+' · '+(ms.indexOf(state.sub)+1)+'/'+ms.length;
}
function trackLine(line){
 let m;
 if((m=line.match(RUN_LINE))){
  state.active=m[1];state.activeDry=line.includes(' --dry-run');
  state.startedAt=Date.now();state.results[m[1]]='run';state.last=null;follow=true;state.sub=null;
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
 const key=lang+'|'+selected+'|'+res;
 if(key!==stepKey){
  stepKey=key;
  const idx=FLOW.indexOf(selected);
  $('stcard').className=m.tone==='danger'?'stage-danger':'';
  $('stnum').textContent=m.num||String(idx+1).padStart(2,'0');
  $('sttitle').textContent=title(selected);
  $('stmeta').replaceChildren(selected,...(m.tag?[tagEl(m)]:[]));
  $('stnote').textContent=st(selected,'note');
  const specs=[[t('spec.effect'),st(selected,'effect'),m.tone==='danger'?'v-warn':''],[t('spec.need'),st(selected,'need'),'']];
  if(m.sudo)specs.push([t('spec.perm'),t('permText'),'']);
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
let off=0,tail='',tailEl=null,follow=true,lineCount=0,dropped=0,gapEl=null,inflight=null;
const ANSI=/\x1b\[[0-9;]*[A-Za-z]/g;
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
  frag.append(lineEl(p));lineCount++;
 }
 if(tail){tailEl=lineEl(tail);frag.append(tailEl);lineCount++}
 logEl.append(frag);
 trimLog();
 renderLogMeta();
 if(follow)logEl.scrollTop=logEl.scrollHeight;
 $('jump').hidden=follow;
}
function clearDisplay(){
 logEl.replaceChildren();tailEl=null;gapEl=null;lineCount=0;dropped=0;
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
function setFeatMsg(key){featMsg=key;$('feats').textContent=t(key)}
function featInputs(){return [...document.querySelectorAll('[data-f]')]}
function selectedFeats(){return featInputs().filter(c=>c.checked).map(c=>c.dataset.f)}
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
}
function renderFlags(){
 const flags=[];
 if($('manual').checked)flags.push(['allow-manual','risk']);
 if($('noid').checked)flags.push([t('flagNoid'),'risk']);
 if($('dp').value)flags.push(['data='+$('dp').value,$('dp').value==='none'?'risk':'info']);
 if($('bootargs').value.trim())flags.push(['boot-args','info']);
 if($('n66ipsw').value.trim())flags.push(['N66 IPSW','info']);
 if($('j96ipsw').value.trim())flags.push(['J96 IPSW','info']);
 $('flags').replaceChildren(...flags.map(([t,c])=>h('span',{class:'flag '+c},t)));
}
async function loadFeats(){
 const t=$('target').value,tok=++featToken,box=$('feats');
 featsReady=false;
 setFeatMsg('feat.loading');
 refreshFeats();render();
 let d;
 try{d=await j('/api/features?target='+encodeURIComponent(t))}
 catch(e){if(tok===featToken){setFeatMsg('feat.loadFail');refreshFeats()}return}
 if(tok!==featToken)return;
 featDefault=d.sel;featMsg='';
 const names=[...new Set([...d.all,...d.sel])].sort();
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
}
function setAllFeats(fn){for(const c of featInputs())c.checked=fn(c.dataset.f);refreshFeats()}
$('target').addEventListener('change',loadFeats);
$('featall').addEventListener('click',()=>setAllFeats(()=>true));
$('featdef').addEventListener('click',()=>setAllFeats(f=>featDefault.includes(f)));
$('dry').addEventListener('change',render);
const drawer=$('drawer');
for(const id of ['fsum','openopts'])$(id).addEventListener('click',()=>drawer.showModal());
$('closeopts').addEventListener('click',()=>drawer.close());
drawer.addEventListener('click',e=>{if(e.target===drawer)drawer.close()});
for(const ev of ['input','change'])drawer.addEventListener(ev,renderFlags);

/* ---------- 阶段 ---------- */
function mkStages(){
 let flowNum=0;
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
  bootargs:$('bootargs').value,dp:$('dp').value,
  n66ipsw:$('n66ipsw').value,j96ipsw:$('j96ipsw').value};
}
function confirmRun(body,meta){
 const edit=meta.sev==='edit',dlg=$('dlg'),items=[[t('dlg.stage'),body.stage],[t('dlg.target'),body.target]];
 dlg.dataset.sev=edit?'edit':'wipe';
 if(FEATURE_STAGES.has(body.stage))items.push(['features',body.features.join(', ')||t('feat.base')]);
 items.push([t('dp'),body.dp||t('dlg.manifest')],['boot-args',body.bootargs.trim()||t('dlg.manifest')]);
 if(body.n66ipsw.trim())items.push(['N66 IPSW',body.n66ipsw.trim()]);
 if(body.j96ipsw.trim())items.push(['J96 IPSW',body.j96ipsw.trim()]);
 if(body.manual)items.push(['allow-manual',t('dlg.on')]);
 $('dlgtitle').textContent=t(edit?'dlg.titleEdit':'dlg.titleWipe',{name:label(body.stage)});
 $('dlgnote').textContent=t(edit?'dlg.noteEdit':'dlg.noteWipe',{ready:t(meta.ready)});
 $('dlgrows').replaceChildren(...items.flatMap(([k,v])=>[h('dt',null,k),h('dd',null,v)]));
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
 notice();
 state.pending=true;render();
 if(matchMedia('(max-width:999px)').matches)$('logpanel').scrollIntoView();
 try{
  const r=await j('/api/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  if(r.reason==='need-sudo')notice('notice.sudo',{stage});
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
});
applyStatic();mkStages();render();refreshFeats();loop();
setInterval(tickTimer,250);
</script></body></html>"""


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
            return self._send(200, {"sel": sel, "all": allf})
        if u.path == "/api/log":
            off = int(parse_qs(u.query).get("off", ["0"])[0])
            lines, total = RUNNER.since(off)
            started = RUNNER.started if RUNNER.running() else 0
            return self._send(200, {"lines": lines, "off": total, "started": started})
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        u = urlparse(self.path)
        if u.path == "/api/stop":
            RUNNER.stop()
            return self._send(200, {"ok": True})
        if u.path == "/api/run":
            n = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(n) or b"{}")
            args = self._build_args(body)
            if body["stage"] in SUDO_STAGES and not body.get("dry") and os.geteuid() != 0:
                RUNNER.put(f"[!] {body['stage']} 需要 root。请用终端运行：\n    sudo "
                           + " ".join(args) + "\n")
                return self._send(200, {"ok": False, "reason": "need-sudo"})
            ok = RUNNER.start(args)
            return self._send(200, {"ok": ok})
        return self._send(404, {"error": "not found"})

    def _build_args(self, b):
        a = [sys.executable, os.path.join(REPO, "n56patcher.py"), b["stage"],
             "--target", b.get("target", "n56-ios13")]
        if "features" in b and b["stage"] in ("build", "boot", "patch-rootfs", "install", "all", "list"):
            a += ["--features", ",".join(b["features"])]
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
