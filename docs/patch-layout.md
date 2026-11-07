# 补丁与系统版本

目标决定固件版本和补丁目录，共用 Flow 决定执行阶段。

```text
n56patcher.py
core/
  flow.py              构建、安装、启动
  patch.py             按目标发现补丁、选择功能、排列依赖
  installation.py      独立系统卷与实际布局

targets/
  _n56.py              设备与工具
  n56_ios13.py         iOS 13.7

patches/
  shared/              设备资源、原生材料、通用移植算法
  ios13/               iOS 13.7 补丁与 ABI
```

补丁目录各自按 `kc/`、`dt/`、`rootfs/` 分层，`impl/` 放实现和布局。共享算法接收版本配置；固定地址和目标 ABI 放在对应系统目录。

补丁 ID 按功能保持一致，例如 `kc.audio`。注册表只加载共享目录和当前版本，功能依赖与执行顺序由 `requires`、`after` 描述。

```sh
python3 n56patcher.py list --target n56-ios13
```

`tools/` 放上游工具、环境初始化及调试入口。系统补丁和安装步骤由主管线调用。
