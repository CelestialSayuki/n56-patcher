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
| 其他（我们创建的槽位） | 允许 | 暂缓实现 |

## donor 快照

覆盖原机 12 System（s1）之前，必须先从设备生成 donor 快照：

- 白名单见 `patches/shared/donor_whitelist.py`，是所有版本需要的设备端文件的并集。白名单以外的文件不拷，白名单内的缺一个就不生成快照。
- 快照保存在 `state/donors/<设备ID>/`，附带 `manifest.json`（路径、大小、sha256）。
- 快照完成后，所有设备端来源（`device_s1`）都从快照读取，不再依赖设备上的原 12 System。
- 只有 12.5.8 rootfs 里有的文件可以从 IPSW 得到。`Mav10` 基带固件、`factorydata`、`sep-firmware.img4` 只能从设备拿，所以快照必须在覆盖之前做。

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

以下步骤代码已写好，离线检查（白名单覆盖、门禁、计划、启动判定）全部通过，但没有在设备上跑过：

- `slots snapshot`：ramdisk 中 ssh 流式拷出白名单
- `slots format` 与安装中的清空：`rm -rf` 清空分区，Data 带 `-o protect`
- 按槽位追加卷（`ensure_slot_volumes`）：卷号必须是容器末尾的下一个
- 快照模式下的 SEP 加载：先把快照中的 SEP 固件送到 ramdisk 再加载
- 同一台设备上 s1 写 13 之后，非活动系统的 role 与启动行为（见 `docs/conclusions.md`）

删卷功能暂缓实现。分区身份识别（哪个分区是哪个系统的 Sys 与 Data）目前依赖槽位记录，role 不作为判据。
