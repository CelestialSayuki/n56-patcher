# 宗卷设置：多系统分区与启动

网页入口：`http://127.0.0.1:8756/volumes`（主界面顶栏“宗卷设置”）。命令行入口：`python3 n56patcher.py slots <动作>`。

## 概念

- **用途**：你声明某个分区打算做什么，例如 `s4 = 13 Sys`。未声明用途的分区不会被用来安装。
- **实际内容**：分区上物理存在的东西，例如 s1 仍是 iOS 12，或者已经清空。donor 门禁看的是实际内容，不是用途。
- **槽位**：一个版本的 System 与 Data 一对分区，对应一套启动包。

## 权限

| 分区 | 格式化 | 删除 |
|---|---|---|
| s3（基带数据） | 禁止 | 禁止 |
| s1、s2（原机 12 System / Data） | 允许，格式化后可另作他用 | 禁止 |
| 其他（我们创建的槽位） | 允许 | 允许；已装版本须成对删除（`--pair`） |

## donor 快照

覆盖原机 12 System（s1）之前，必须先从设备生成 donor 快照：

- 白名单见 `patches/shared/donor_whitelist.py`，是所有版本需要的设备端文件的并集。白名单以外的文件不拷，白名单内的缺一个就不生成快照。
- 快照保存在 `state/donors/<设备ID>/`，附带 `manifest.json`（路径、大小、sha256）。
- 快照完成后，所有设备端来源（`device_s1`）都从快照读取，不再依赖设备上的原 12 System。
- 只有 12.5.8 rootfs 里有的文件可以从 IPSW 得到。`Mav10` 基带固件、`factorydata`、`sep-firmware.img4` 只能从设备拿，所以快照必须在覆盖之前做。

## 删卷

`python3 n56patcher.py slots delete sN [--pair]`，需要 ramdisk。

- 删除前先卸载分区的所有挂载点，然后调用 ramdisk 自带的 `/sbin/apfs_deletefs /dev/disk0s1sN`（参数是设备名）。
- 工具输出 `Successfully deleted fs` 才算成功，之后再核对容器中已没有该卷。
- 删除后分区号记入 `released`，不再分配。新建卷时用计划的号码显式指定 `fsindex`，允许留空洞。
- 已装版本的 Sys 与 Data 必须一起删（`--pair`），同时删除该版本的启动包目录。
- s1、s2、s3 不能删，规则见 `core/slots.py:delete_targets`。

依据：我们挂载了 SSH ramdisk 镜像（`tools/SSHRD_Script/sshramdisk/ramdisk.img4`，HFSX 根文件系统），
里面有 `sbin/apfs_deletefs`（链接 APFS.framework 的 `APFSVolumeDelete`）、`sbin/newfs_apfs`、
`apfs.util`。

## 分区识别

`python3 n56patcher.py slots identify`，需要 ramdisk。它不看 role，而是看分区上的内容：

- **System 卷**：只读挂载后，有 `System/Library/CoreServices/SystemVersion.plist` 即为 System，build 映射到版本（`VERSION_BY_BUILD`）。
- **Data 卷**：有标记文件 `/.n56-slot`（内容为版本号，安装收尾时写入）即为 Data。加密卷需要用 `-o protect` 挂载，挂载失败则归类为“未知”，不会猜。
- **s2、s3 不挂载**：s2 是原机 DataA（加密，不要在 ramdisk 中挂载），s3 是基带数据。

已装版本的配对结果：`ok`（与记录一致）、`mismatch`（类型或版本对不上，需要人工处理）、`unknown`（加密且无法挂载，无法确认）。

为什么不用 role：我们挖出的 `newfs_apfs` 会报 `Volume role %d already exists in container`，说明 role 在
建卷时有唯一性约束；但我们的 `set_roles` 直接改超级块，绕过了这个检查。role 在设备上到底是什么状态取决于
走哪条路径，不能当作识别依据。

## 安装与启动联动

```sh
python3 n56patcher.py slots assign s1 "13 Sys"      # 声明用途
python3 n56patcher.py slots assign s2 "13 Data"
python3 n56patcher.py slots plan 13                  # 预览步骤，不碰设备
python3 n56patcher.py slots install 13               # 卷 → 清空 → rootfs → 补丁 → 启动包 → 记录
python3 n56patcher.py slots boot 13                  # 启动前判定，过期则重建，然后启动
```

- 安装步骤里，目标 Sys 和 Data 会先被清空，然后流式写入 rootfs。写入前门禁已检查。
- 启动包绑定到该槽位的 System 分区（`rd=disk0sXsN`，`root_part`）。
- 启动包过期的判定：启动输入（bootargs、挂载、features、donor 快照指纹）的哈希与记录不一致。
- 过期时：绑定已确认、内容记录与用途一致，才自动重建；否则需要 `--confirm`。
- 半装一律按已装处理。安装中断后，用户手动格式化或删分区，不做续装。

## 未在真机验证的部分

以下步骤代码已写好，并用假 ramdisk 或离线检查覆盖了判定逻辑，但没有在设备上跑过：

- `slots snapshot`：ramdisk 中 ssh 流式拷出白名单
- `slots format` 与安装中的清空：`rm -rf` 清空分区，Data 带 `-o protect`
- 按槽位建卷（`newfs_apfs -o fsindex`，`ensure_slot_volumes`）
- `slots delete`：`apfs_deletefs` 的实际输出与删后的容器状态
- `slots identify`：只读挂载、`SystemVersion.plist` 与 `/.n56-slot` 的读取；加密 Data 用 `-o protect` 能否挂载
- 快照模式下的 SEP 加载：先把快照中的 SEP 固件送到 ramdisk 再加载
- 同一台设备上非活动系统的启动行为（见 `docs/conclusions.md`）
