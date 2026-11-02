# N56 iOS 13.7 技术结论

目标：iPhone 6 Plus（N56AP / iPhone7,1）在 iOS 12.5.8 SystemA 之外启动第二系统 iOS 13.7。项目已跑通，最终启动包同时包含硬件适配、DataB 解密和 checkra1n。

## 启动链与系统组成

- 启动顺序：gaster → iBSS → iBEC → DeviceTree → TrustCache → KernelCache → `bootx`，全部组件用本机 IM4M 签名。
- 版本来源：内核与基础 rootfs 取 J96 17H35；Health、电话、Wallet 等 iPhone App 与设置资源取 N66 17H35；机型文件、基带和 Wi-Fi 固件取设备 SystemA 16H88。
- 卷布局：s1 System（iOS 12）、s2 Data、s3 Baseband Data（role `0x80`）、s4 SystemB（role `0x1`）、s5 DataB（role `0x40`）。
- 启动所需的 TC 必须与设备上的 mrm 及新增二进制配套。mrm 或 Mach-O 改动后要重建 TC。
- 刷机后 APTicket 会变，必须重新执行 `extract-im4m`。
- 写入设备前不能用 `noowners` 方式挂载 DMG，否则属主会变成 `501:20`。

## PMU 与 Oscar

- 最终方案是 iOS 13 `AppleD2207PMU` 按 N56 寄存器布局适配，RTC 保持启用，watchdog personality 禁用。
- GPIO 修正：`0xfffffff006da049c` 保留掩码 `0x1d → 0x05`；`0xfffffff006da04d0` 输出值 2 的位编码 `0x40 → 0x10`。
- Oscar 固件、`oscard`、`locationd`、CoreMotion 必须都用 iOS 13 版本。混用 iOS 12 固件和 `oscard` 时活动识别没有回调。
- AppleOscar、AppleOnboardSerial、SoC GPIO 用 J96 17H35；AppleSamsungSerial 的 UFCON 选择改为 N56 原生取值（`0x1f1`、`0x1c1`、`0x1c1`，掩码 `0xff`），实现在 `patches/kc/pmu_d2186.py`。
- 从 tvOS 13 移植原生 `AppleD2186PMU` 的方案已放弃：驱动能进入用户空间，但 Wi-Fi、蓝牙、基带和传感器出现广泛回归。
- 把事件范围从 14 改成 13 不能修复 timesync，事件范围保持 14 字节。

## 硬件用户态

- Wi-Fi：除 `kc.wifi` 的哈希补丁外，还要部署 `usr/share/firmware/wifi/C-4345__s-B1/` 的 `barbera.trx`、`barbera.clmb`、`barbera.txcb`、`P-barbera_M-CORO_V-m__m-5.1.txt`，来源是 SystemA。
- 基带需要同时满足：
  - dyld cache 内 CommCenter 产品表能识别 N56；
  - Mav10 固件同时位于 `usr/standalone/firmware/Baseband/` 和 `usr/local/standalone/firmware/Baseband/`，来源是 SystemA；
  - `Carrier Bundles/iPhone/` 来自 N66；
  - s3 role 为 `0x80`，并且修改后 dyld cache 的 cdhash 进入 TC。
- Health：去 stub 化抽取后，跨库直接分支会失效，要重指向已有 stub。资源、二进制和 cdhash 必须成套部署。
- `installd`：修正空 Application 容器集合的处理后，首个免费签名 App 才能安装。
- `backupd`：异常 `Null backup UDID` 来自 `-[MBServiceCache addBackup:lastModified:]`。文件偏移 `0x127dc4` 改 `200900b4 → a00500b4`，无 UDID 记录直接返回，有效记录照常写库。

## SEP 与 DataB 加密

- 设备运行 iOS 12 sepOS，iOS 13 内核默认的 class-M 请求（tag 7/8）和 v1 请求体不被接受，错误为 `-13`。
- 容器 keybag 由 SEP/硬件密钥包裹，不是用容器 UUID 加密，不能离线解析或伪造。
- 解决方法是让 iOS 13 内核走保留的 v0 编码器和 tag 1/2 旧格式：
  - 媒体密钥：SKS 49 创建、SKS 50 解包；
  - 逐文件密钥：SKS 9、15、16；
  - 另跳过 class-M 迁移。
- 实现为 `patches/impl/kc/legacy_data.json` 的 10 个区域：`0xfffffff005f31c40` 的 316 字节桥、AppleSEPKeyStore 七处调用/分支修改、APFS `0xfffffff006904154` 与 `0xfffffff00690429c` 两处修改。缺少这些字节时，AKS unwrap 返回 `0xe007c00d`，DataB 挂载失败。
- 新 DataB 的 `systembag.kb` 由 iOS 12 ramdisk 的 `MKBKeyBagCreateSystem` 创建；iOS 13 `keybagd --init` 只加载，不生成。
- 创建 systembag 时要保留现有 `BAG1` 包裹材料（`KBSaveSystemBagHandle` 第 5 参数改为 1），否则会替换设备全局的 EffaceableStorage 记录，影响 DataA。
- 不要在 ramdisk 中挂载 s2 或加密的 s5。
- ramdisk 启动时 SEP 未加载（`seputil --ping` 返回 `ping failed`）。此时 `newfs_apfs -P` 建 DataB 会一直卡住，容器被锁，连只读挂载 s1 也超时，只能重启。流程改为建卷前先加载 SEP，这个顺序尚待全新安装验证。

## checkra1n

- 不走 PongoOS 启动：KPF 在构建时直接写入 raw KC，用户态固化到 SystemB。
- 顺序不能变：KPF 必须跑在原始 J96 KC 上，之后再合并通用启动补丁和硬件 transforms。通用补丁后的 KC 在 `amfi_sha1` 处匹配失败。
- 五个 shellcode 函数指针改为相对表项的偏移，随 KC 一起滑动。
- `Missing kernel_cache_addr` 的原因是 kernel task 的 `TASK_DYLD_INFO` 为空。KC 在 BSD 初始化时自行发布 offsetcache：
  - hook 位于 J96 内联 `IOKitBSDInit` 路径 `0xfffffff007490e78`（文件偏移 `0x48ce78`），独立导出函数 `0xfffffff00766d548` 不在运行路径上；
  - `_kernel_task` 在 `0xfffffff007091ab8`，`vm_kernel_slide` 在 `0xfffffff007096268`；
  - task 字段 `all_image_info_addr=0x3c8` 指向 blob，`all_image_info_size=0x3d0` 按协议保存 slide；
  - flags 为 `0`，capability 为 `3`，共 7 个键，blob 344 字节。
- 用户态：`/binpack`、`com.n56.checkra1n` 启动 job、`loaderd` 自启动；USB SSH 监听设备 44 端口，主机用 `iproxy 2222 44` 转发。

## TrustCache 配套

干净构建的 KC、iBSS、DeviceTree 与实机启动包逐字节一致。iBEC 内嵌 boot-args，去掉 `serial=3` 后内容随之改变。TC 条数相同（2238 条），连续两次构建结果相同，但与当前设备的 TC 有 3 条不同，来自用户态：

| 构建侧 cdhash | 对应文件 | 与设备的关系 |
|---|---|---|
| `fbcae34e…` | 构建生成的 mrm | 设备 mrm 为 `2c08a843…`，比构建版少部分 App Extension 条目，其余键值相同 |
| `b55f90e8…` | `/binpack/usr/bin/n56-jb-info` | 设备上没有此文件 |
| `aa9ddae2…` | `/Applications/loader.app/loader` | 设备上的文件 cdhash 相同，但设备 TC 未收录，Loader 是启动后安装的 |

设备 TC 另有 `718d4f0c…`、`94f03f31…` 两条，在设备的 `/binpack`、Loader 和 checkra1n 目录中都没有对应文件，来源未定位。

因此：

- 新 TC 只能配合同一次构建写入的 rootfs，全新安装时 mrm 和 TC 成套生成。
- 已安装设备继续使用安装时配套的启动包，直接换新 TC 时设备 mrm 的 cdhash 不在其中，launchd 会拒绝。
- 刷机后旧启动包作废，需重提 IM4M 并全新安装，生成新的成套启动包。

## 管线补齐的安装步骤

- systembag：`rootfs.finish` 在加密模式下加载 SEP 固件、挂载 DataB（先试 `-o protect`，失败则普通挂载），再用 `tools/systembag/create_systembag.c` 和打过 `PRESERVE_BAG1` 补丁的 ramdisk `MobileKeyBag` 创建。助手与补丁已和旧版比对，这组挂载和加载顺序按旧记录重建，尚待全新安装验证。
- Cydia：`rootfs.cydia` 下载 Loader 使用的 `strap.tar.lzma`、`cydia.tar.lzma`（SHA-256 固定），解包到 SystemB。首次开机由 `n56-init.sh` 执行 `dpkg --configure -a` 和 `uicache`，日志为 `/var/log/n56-cydia.log`，成功后创建 `/.bootstrapped`。
