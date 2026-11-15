# 宗卷设置：多系统分区与启动

网页入口：`http://127.0.0.1:8756/volumes`（主界面顶栏“宗卷设置”）。命令行入口：`python3 n56patcher.py slots <动作>`。

## 概念

- **用途**：你声明某个分区打算做什么，例如 `s4 = 13 Sys`。未声明用途的分区不会被用于安装。
- **实际内容**：分区上物理存在的东西，例如 s1 仍是 iOS 12，或已经清空。donor 门禁看的是实际内容，不是用途。
- **槽位**：一个版本的 Sys 与 Data 一对分区，对应一套启动包。

## 权限

| 分区 | 格式化 | 删除 |
|---|---|---|
| s3（基带数据） | 禁止 | 禁止 |
| s1、s2（原机 12 System / Data） | 允许，清空后可另作他用 | 禁止 |
| 其他（我们创建的槽位） | 允许 | 允许；已装版本须成对删除（`--pair`） |

## 设备身份

- 设备 ID 是设备的 ECID，自动读取，不再手动填写。
- DFU 阶段（ramdisk 启动前）用 `irecovery -q` 读取 `ECID:`；ramdisk 内用 `ioreg -p IODeviceTree -k unique-chip-id` 作为备用（未在设备上验证）。
- 第一次读到时写入宗卷记录。之后每次连接都会核对：不一致就拒绝执行，并提示用 `slots rebind-device` 改绑。
- 安装路径（`slots install` 与 `--slot`）也会在清空分区之前核对身份。
- 快照目录按这个 ECID 分开保存在 `state/donors/<ECID>/`。

## donor 快照

覆盖原机 12 System（s1）之前，必须先从设备生成 donor 快照：

- 白名单见 `patches/shared/donor_whitelist.py`，是所有版本需要的设备端文件的并集。
- 快照保存在 `state/donors/<设备ID>/`，附带 `manifest.json`（路径、大小、sha256）。白名单缺一个就不生成快照。
- 快照可用后，设备端来源（`device_s1`）、SEP 固件、B1 固件、bluetoothd 都从快照读取。
- 目标为 s1，或者 s1 上已经不是原机 12 系统时，安装必须有快照，否则拒绝（不会去读错误的分区）。
- 12.5.8 的 rootfs 里没有 `Mav10` 基带固件、`factorydata`、`sep-firmware.img4`，只能从设备拿，所以快照必须在覆盖之前做。

## 分区识别（统一）

所有判断"这个分区是什么"的地方都用 `core/volume_identify.py`：`status`、旧的独立卷清单、`identify`、`adopt`。宗卷安装的卷名核对只读取卷的名字（不挂载），与槽位记录对照。不再有另一套按角色、名字或卷号的猜测。

- System：未加密卷只读挂载后，存在 `SystemVersion.plist`。
- Data：存在根目录标记 `/.n56-slot`。未加密卷直接读；加密卷只在 deep 模式下用 `-o protect` 挂载。
- 原机布局是约定：s2 为原机 DataA、s3 为基带，都不挂载。
- 配对只按版本：System 的版本与 Data 的标记相同才算一对。没有标记的 Data 不按名字配对。
- `status`、旧的独立卷路径（卷名由配置约定）都不挂载加密卷，结果为未知；只有 `identify` 用 deep 模式。

## 版本标记与认领

- 安装收尾时，在 Data 卷根目录写入 `/.n56-slot`（内容为版本号）。System 卷靠 `SystemVersion.plist` 识别。
- 早于标记功能安装的系统，或者安装没有走完的，Data 卷没有标记。它们的配对结果是 `unknown`（未标记），不是 `mismatch`。
- 认领：把 `sN` 声明为 `<版本> Sys`、`sM` 声明为 `<版本> Data` 后，运行 `slots adopt <版本>`。它检查 Sys 的版本，给 Data 写入标记，然后记录为已装（`adopted`）。认领不记录启动包，启动前需要 `boot --confirm` 重建。

## 删卷

`python3 n56patcher.py slots delete sN [--pair]`，需要 ramdisk。

- 删除前先卸载分区的所有挂载点，然后调用 ramdisk 自带的 `/sbin/apfs_deletefs /dev/disk0s1sN`。
- 工具输出 `Successfully deleted fs` 才算成功，之后核对容器中已没有该卷。
- 每删成功一个就释放它的号码（记入 `released`，不再分配）。整组删完后才清理安装记录与启动包；中途失败时，残缺的记录保留，状态检查会显示出来。
- 已装版本的 Sys 与 Data 必须一起删（`--pair`）。

依据：ramdisk 镜像（`tools/SSHRD_Script/sshramdisk/ramdisk.img4`，HFSX 根）里有 `sbin/apfs_deletefs` 和 `sbin/newfs_apfs`。
在 Mac 上用同样格式的 APFS 容器验证过：删掉中间的卷后，其他卷号不变，删掉的号留下空槽，不会压缩。

## 格式化与重装

- `slots format sN` 清空分区内容（文件级，`rm -rf`），Data 卷用 `-o protect` 挂载（需要 SEP）。
- 格式化任一分区，都会清除所属版本的安装记录与启动包。之后重新声明、再安装即可，不需要先删分区。
- 安装时 Sys 必定清空；Data 默认清空。

### 实验性：保留原数据

`--keep-data`（网页安装按钮旁的复选框，标为实验性）让安装不清空 Data 卷。Sys 仍会被清空。它依赖 iOS 13 对原有 keybag 与数据的兼容性，未在设备上验证。

## 识别命令

`python3 n56patcher.py slots identify`，需要 ramdisk。对全部卷做 deep 识别，结果写入记录，并核对已装版本。

配对结果：`ok`（一致）、`unknown`（未标记或加密卷无法挂载，需要人工确认或认领）、`mismatch`（类型或版本对不上）。

为什么不用 role：`newfs_apfs` 建卷时会检查 `Volume role %d already exists in container`，说明角色有唯一性约束；但 `set_roles` 直接改超级块，绕过了这个检查。role 不能作为判据。

## 安装与启动联动

```sh
python3 n56patcher.py slots assign s4 "13 Sys"       # 声明用途
python3 n56patcher.py slots assign s5 "13 Data"
python3 n56patcher.py slots plan 13                   # 预览步骤，不碰设备
python3 n56patcher.py slots install 13                # 卷 → 清空 → rootfs → 补丁 → 启动包 → 记录
python3 n56patcher.py slots boot 13                   # 启动前判定，过期则重建，然后启动该系统
```

- 启动包的哈希只由启动组件决定：bootargs、挂载、补丁选择、保护模式。donor 只影响 rootfs，不进入哈希。
- 启动包过期的判定：启动输入的哈希与记录不一致。绑定已确认、内容记录与用途一致时自动重建；否则需要 `--confirm`。
- 半装一律按已装处理。它不做续装；需要重装时，先格式化其中任一分区。

## 命令行与网页的写入

所有写入 `state/volumes.json` 的操作都通过 `slots.mutate`：加文件锁、读取、修改、保存。CLI 与网页同时写入不会互相覆盖。

## 未在设备上验证

以下步骤代码已写好，判定逻辑用假 ramdisk 或 Mac 上的 APFS 容器覆盖过，但没有在 iOS 设备上跑过：

- `slots snapshot`：ssh 流式拷出白名单
- `slots format` 与安装中的清空：`rm -rf`，Data 带 `-o protect`
- 按计划号建卷（`newfs_apfs -o fsindex`）
- `slots delete`：`apfs_deletefs` 的实际输出与删后的容器状态（iOS 上）
- `slots identify` 与 `slots adopt`：只读挂载、标记的读写、加密 Data 的 `-o protect` 挂载
- 设备 ECID：`irecovery -q` 在 DFU 下的输出格式，`ioreg -k unique-chip-id` 的输出格式
- 快照模式下的 SEP 加载
- `--keep-data`
- 同一台设备上非活动系统的启动行为（见 `docs/conclusions/13.md`）

## 尚未解决

- 设备上的 `ioreg` 读取与 `irecovery -q` 的 ECID 行为，还没有在真机上确认。
- 删卷、识别、认领、保留数据，都还没有在真机上验证。
