# PROFILE-ROG9PRO 真机门禁：ASUS ROG Phone 9 Pro 国行 `6.6.127` 新 profile（select_stack，app 流程）— PASS

本次验证的是**一份新 profile**，不涉及仓库代码改动，所以没有"对应提交"。
APK 用的是上游官方 pre-release（从 `main` 构建）：GhostLock **1.2+564**，
build `2026-10-07 18:05:45`。profile 由 `tools/extract_rs` 从本机 OTA 镜像生成后手工核对，
**尚未进 `index.conf`**（成功率未跑满，见「保留项」）。

静态推导与证据链在适配记录里，不在本文重复：设备身份、OTA 的 HTTP Range 部分提取、
C1–C5 的逐项核对。本文只记真机。

## 设备与入口

- 型号 **ASUSAI2501**（ROG Phone 9 Pro 国行），序列号前缀 `SBAI…`
- `ro.build.fingerprint` = `asus/CNAI2501/ASUSAI2501:16/BQ2A.250525.001/36.0810.1810.84:user/release-keys`
- `uname -r` = `6.6.127-android15-8-g74246892e200-ab15480978-4k`，
  build `Fri May 22 09:40:40 UTC 2026`，clang 18.0.0 `+pgo +bolt +lto +mlgo`
- 入口：**app 流程**（app 内导入 `.conf` 后点运行），`uid=10373` / `untrusted_app` /
  有 zygote seccomp 过滤器（所以 W3 必须跑）
- route = `select_stack`（来自 profile），`waiter_shift = -2`
- 管理器：KernelSU **v3.3.0 (32601)**，提供 `libksud.so`（4892712 B）
- `enforce=unreadable`：enforcing 下 `untrusted_app` 读不到 `/sys/fs/selinux/enforce`，
  这是 W1 验证判据的基础（见「结果」）

### 固件说明（重要）

设备固件是 `36.0810.1810.**84**`，而官网能下到的只有 `.86`。**没有为了门禁升级设备**，
因为 `.86` 的安全补丁级别更高。判定两者**内核二进制相同**的依据：

- 设备 `/proc/config.gz` 与 `.86` 镜像内嵌的 IKCFG blob **逐字节相同**
  （均 211778 B，SHA-256 `f3be4cd7…6388d0`）
- `uname -r`、build 时间戳、`ab15480978` 三项全同

即 ASUS 只提升了 userspace 的补丁级别，没有重建内核。这是**强证据而非证明**，记为保留项。

## 哈希

| 对象 | SHA-256 |
|---|---|
| `boot.img`（从 `.86` OTA 部分提取） | `5af00f44ce93bddd800ae4c3e320e62ff5e6517844159966a6ad60a601ba41c5` |
| `xbl_config.img` | `7a687bc79e2fc1f77531449f43bbe03df13ba7817374c7d2fb017c6c8430e5d6` |
| `uefi.img` | `12c964c9448cbb538b426dc13f66b34a32773f13b50d44b6ad7ea98732989e97` |
| 候选 profile（运行 #1–#4 用的那份，不带 `execution`） | `099827ded6d94832f6bb192f49821e2901dc4d68f82bf07f03d6ebb88ff17949` |
| 门禁后的 profile（加了 `execution.recommended_cpus`，`main` 分支变体） | `71008cbf678f87a8e6ba9806766dd6375c941b08a5d76bf3433c6a3d0afaf899` |
| 门禁后的 profile（带 `vr_guard` 段的主文件） | `38c70c9b99054cdf3ecae0cda7aaedf8a2dee86357cd77afcb329c6c4baf91bb` |

运行时用的是 `main` 变体：上游 `main` 的 `ProfileResolver.KnownTopLevel` 不含
`recommend_vr_guard` / `vr_guard`（那两个键只在 `vr-ko-bypass-dev`），带着会被
`validateMerged` 判 `unknown top-level key` 拦住。两份的几何偏移完全一致。

## 结果

**PASS。** `cpu6/7` 上 2/2 成功，其中一次是冷机、零重试。

### 运行表

| 运行 | CPU 对 | uptime | 结果 | `prepare_kernel_page` | 耗时 | 日志 |
|---|---|---|---|---|---|---|
| #1 | 4/5 | 16003 s | **FAIL** — `W1: SELinux attempt 15/15` 全败 → `Write 1 failed` | 15/15 全是 `ok attempt=1` | — | `run1-cpu45-w1-fail/` |
| #2 | 4/5（推定） | 16278 s | **FAIL — kernel panic**，过了 W1，在 W2 附近整机黑屏复位 | 未知（trace 丢失） | ~32 s 后崩 | `run2-panic-no-trace/` |
| #3 | **6/7** | 2158 s | **PASS** 全链路 | 8 ok / **18 retry** | 60.2 s | `run3-cpu67-ok/` |
| #4 | **6/7** | **54 s（冷机）** | **PASS** 全链路，W1/W2 均第 1 次过 | 6 ok / **0 retry** | **22.6 s** | `run4-cpu67-ok-coldboot/` |

运行 #1 与 #2 是**同一次开机**（相隔 275 s），运行 #3 与 #4 的生效 profile
**逐字节相同**，差别只有冷机。

### 运行 #4 的 stage 链（完整通过）

```
W1: SELinux attempt 1/15 → target=0xffffff802a37a0e8 mode=1
  prepare_kernel_page ok attempt=1 +670ms
  route_done status=0 clean=1/1 step=0 errno=0 calls=1 success=1
  [T+3619ms] Write 1 complete
child_pid=16360 child_task=0xffffff894b8addc0
vr.ko not loaded; skipping tag clear
W2: cred attempt 1/15 → target=0xffffff894b8ae5e0 mode=2
  route_done status=0 ... success=1 → child uid = 0 → child is root!
W3-0: leaf dir ×2 → W3: TIF_SECCOMP ×1 → W3: seccomp mode
  child seccomp filter bypassed (finit_module errno=22)
  child seccomp fully bypassed (forked workers run filter-free)
[T+22593ms] exploit complete
[ksu] policyload before=0 after=2 / policy fixup rc=0
[ksu] late-load kmi=android15-6.6 / late-load exit=0
[ksu] KernelSU module loaded
native exited code=0 / enforce=1 (enforcing) / KernelSU ready
```

6 次 route 调用全部 `status=0 clean=1/1 success=1`。
`/proc/modules` 事后含 `kernelsu 167936`。无 panic、无重启。

### 运行时确认掉的偏移

- **`task_struct.cred = 2080`**：`child_task=0xffffff894b8addc0`，
  W2 target `0xffffff894b8ae5e0`，差 `0x820` = 2080 = profile 的值。
- **`selinux_state.enforcing`**：target `0xffffff802a37a0e8` 由
  `kernel_phys_load 0xa8000000 + (image 0x237a0e8 − KIMAGE_TEXT_BASE)
  − phys_offset 0x80000000 | P0_PAGE_OFFSET` 精确重现，且写入后
  `/sys/fs/selinux/enforce` 变为可读。
- **`kernel_phys_offset` 留 `null` 是对的**：native 回退到编译默认 `P0_PHYS_OFFSET`
  (`0x80000000`)，与 `xbl_config` FDT 里最低区段基址一致（26 行内存图，
  `scripts/xbl_memory_map.py` 读出），且 W1 落地本身即为证明。

## 失败剖析（运行 #1 / #2）

**根因：CPU 对 4/5 不可用。** 与 profile 的几何无关 —— 运行 #3/#4 用同一组地址通过。

证据链：

1. 运行 #1 的 15 次尝试里 `prepare_kernel_page` **每次都 `ok attempt=1`**、
   `route_done success=1` **每次都出现**，但 `attack::check_selinux_off()` 始终返回 0。
   该函数是 `open("/sys/fs/selinux/enforce")`，enforcing 下 `untrusted_app` 被拦住，
   所以"能打开"即证明写落地 —— 验证判据本身是可靠的，失败就是真没写进去。
2. 运行 #1 与 #2 **同一次开机**，地址是常量。运行 #3 在同一地址上通过
   → **整类地址/物理基址假设（含 EFI stub 物理 KASLR）出局**，不需要 `/proc/iomem`。
3. 换成 `cpu6/7` 后 `prepare_kernel_page` 反而大量重试，但写**每次都落地**。
   → "每次都一次就成"是**假成功签名**：堆准备锁到的不是目标页。
4. 运行 #2 的 panic 与运行 #1 的"无反应"是同一根因的两种表现：
   往随机物理页写入，运气不同。换 6/7 后两种都消失。

已排除的其它假设（均留证据）：`kernel_phys_offset` 缺失、`selinux_enforcing` 字段语义
（`CONFIG_SECURITY_SELINUX_DEVELOP=y` + `CONFIG_RANDSTRUCT_NONE=y`）、profile 校验
（`invalid=0`）、`uname -r` 不匹配、vr.ko tag 盲写（本机 492 个模块无 `vr` 前缀，
日志确认 `vr.ko not loaded; skipping tag clear`）。

### 行动项（已完成）

- profile 加上 `execution.recommended_cpus = 6/7`。不加的话 app 用按簇自动配对的
  默认值 4/5，等于把后来者推到会 panic 的那条路上。先例：
  `app/src/main/assets/kernel_profiles/{5.15.167-…,6.1.145-…}.conf` 同样带这一项。
- `.claude/skills/kernel-profile-port/SKILL.md`：阶段 4 增「两个不在 profile 里、
  但决定成败的变量」；W1 排查顺序改为**先重跑 → 再换 CPU 对 → 最后查地址**；
  新增陷阱 T13（profile 不带 CPU 对）、T14（多设备 adb 歧义）。
- `scripts/gate_watch.sh`：见下。

### 记录工具本身的失败

运行 #2 的 trace **一个字节都没留下**，教训值得单列：

1. **exploit 的输出不进 logcat。** 主机侧 4.1 MB 的 logcat 里
   `prepare_kernel_page` / `[spray]` / `=== W1` / `<k>` 命中数全为 0；关于 ghostlock
   只有 auditd 的 avc 回显。那些行只写进 app 的
   `Download/ghostlock-debug-log/<时间戳>/*.log.txt`。
2. **那个文件 panic 后连目录一起消失。** `DebugAttackLog.append` 每行 `flush()` 但
   **不 fsync**，文件经 MediaStore 创建；panic 后 f2fs 回滚到上一个 checkpoint，
   `adb pull` 回来只有上一次运行的目录。
3. **pstore 兜不住。** `/sys/fs/pstore` 对 shell 不可读，app 取得 root 后自己 dump
   的 `pstore/` 目录是**空的**（无可读 ramoops）。

→ `scripts/gate_watch.sh` 改为同时抓两路：logcat（panic 行、avc、掉线时刻）+
设备侧 trace 的**轮询快照**（默认 0.5 s，按路径分组、同路径内只在变长时替换）。
另加多设备 `GL_SERIAL` 钉选，和冷机提示。陷阱表 T8 已按此重写。

## 日志

工作区 `~/Downloads/ghostlock/ASUS-ROG9Pro/logs/`，每个目录含 `identity.txt`、主机侧 `logcat.log`、
`device-debug-log/<时间戳>/`（`ghostlock-direct-0.log.txt` + 生效 `profile.conf` /
`profile.bin`，成功的运行另有 `kernel-info.txt` / `ksu.log`）：

- `run1-cpu45-w1-fail/` — 设备侧 `20261007-224252/`
- `run2-panic-no-trace/` — 无设备侧 trace（见上）
- `run3-cpu67-ok/` — 设备侧 `20261007-232507/`
- `run4-cpu67-ok-coldboot/` — 设备侧 `20261007-233535/`，主机侧 `device-trace.log` 14960 B

脱敏：公开摘录只保留 stage 行与内核地址，不含序列号 / 包名清单 / 网络信息。

## 保留项

1. **成功率未跑满。** 6/7 上 2/2。阶段 4 要求同配置约 15 次才能谈成功率，
   **因此尚未加入 `index.conf` / `SUPPORTED_DEVICES.md`**。
2. **固件 `.84` vs `.86` 是强证据而非证明**（见「固件说明」）。要升级为证明，
   需在设备 root 后 dump 自身 `boot` 分区与 `.86` 的 `boot.img` 对比。
3. **`vr_guard` 段未经真机验证。** 本机无 vr.ko，用的是去掉该段的 `main` 变体。
   带 `vr_guard` 的主文件只做过静态核对。
4. **`KernelSnitch mm_struct leak failed` 仅在非冷机出现**（运行 #3 的 15 次 vs
   运行 #4 的 0 次）。按陷阱 T4 **不**调整 `kernelsnitch.mm_struct_sz`。
5. **运行 #2 的 panic 未定位到具体行**，trace 已永久丢失。根因判为 CPU 对
   （见「失败剖析」），但没有该次运行的直接证据。

## 变更说明

本次验证针对的不是行为差异，而是**一条新设备/内核线的 profile 可用性**：
`6.6.127-android15-8` + 高通 8 Elite + ASUS 国行固件上，`select_stack`
（`waiter_shift = -2`）可用，`task_struct` / `cred` / `offset` 三组几何正确，
app 流程能走到 `KernelSU ready`。

同时修正了 skill 里一条写错的判据：原文写「`W1 attempt N/N` 全败是稳定失败，
因此是地址错」。本次证伪 —— 同一次开机里同一份 conf 一败一成，而真正的判别量是
CPU 对。阶段 4 的排查顺序已据此重排。
