# 工具

macOS 安装完整 Xcode（`n56-jb-info`、`create_systembag` 需要 iPhoneOS SDK）后，在仓库根目录运行：

```sh
python3 -m pip install -r requirements.txt
python3 tools/setup.py
```

| 上游 submodule | 用途 | 本地路径 |
| --- | --- | --- |
| [SSHRD_Script](https://github.com/verygenericname/SSHRD_Script) | gaster、irecovery、iBoot64Patcher、KPlooshFinder、sshpass、iproxy | `tools/SSHRD_Script/Darwin/` |
| [img4lib](https://github.com/xerub/img4lib) | IMG4 解包、封装 | `tools/img4lib/img4` |
| [dualra1n](https://github.com/dualra1n/dualra1n) | Kernel64Patcher、kairos、dtree_patcher；iOS14 的 fsck 与 apfs.fs | `tools/dualra1n/binaries/Darwin/`；复制到 `donors/projects/dualra1n-bin/apfsios14` |
| [gaster](https://github.com/verygenericname/gaster) | DFU 利用与 iBoot 解密，从源码构建 | `tools/SSHRD_Script/Darwin/gaster` |
| [devicetree-parse](https://github.com/khanhduytran0/devicetree-parse) | DeviceTree 解包与重打包 | `tools/devicetree-parse/devicetree-repack` |

版本固定在 submodule gitlink，可用 `git submodule status` 查看。setup 只拉取所需工具；img4 使用上游 lzfse 和 macOS CommonCrypto 本地构建。dualra1n 使用稀疏检出，仅展开 Darwin 工具和许可证。

setup 还会下载官方 [checkra1n 0.12.4](https://checkra.in/releases/) DMG，校验 SHA-256 后把用户态提取到 `donors/checkra1n/`，见 `tools/fetch_checkra1n.py`。

本机额外工具可放在 `tools/bin/`。
