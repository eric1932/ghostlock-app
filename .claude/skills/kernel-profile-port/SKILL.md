---
name: kernel-profile-port
description: 为新内核 / 新机型适配 GhostLock kernel profile：收集设备身份、从官方 OTA 取本机镜像、生成候选 profile、静态核对 offset、真机门禁、归档落库。当任务涉及新设备适配、新的 uname -r、从 boot.img / OTA 提取偏移、profile 字段校验、route 选择，或"这台机器能不能跑 / 为什么打偏"时使用。
---

# 新内核 profile 适配（找 offset）

目标：把一台设备从「不在内置列表」变成「一份经真机验证、可归档的 profile」。

本 skill 只产出 profile（几何 + 调参），不改 `src/core/**`，因此**不触发** `cmp_disasm`
8 函数门禁。一旦需要动攻击路径或 wire 格式，退出本流程，走 AGENTS.md 的 L 级设计流程。

先读：`docs/kernel_profiles/README.md`（工作流）、`PROFILE_SCHEMA.md`（字段 + §3 必填矩阵）。
本文不重复字段表，只给**顺序、判据和已知陷阱**。

## 三条不变量（违反其一就停）

1. **`uname -r` 相同 ≠ 内核二进制相同。** 偏移必须来自**这台设备自己的固件镜像**。
   内置 profile 按精确 `uname -r` 匹配，所以别家厂商的同名 profile 会被选中并静默打偏。
2. **extractor 的输出是候选种子，不是成品。** 「生成成功」≠「可用」。
3. **没过真机门禁的 profile 不标 supported，不覆盖同名内置文件**（另起文件 + 独立 index 条目）。

---

## 阶段 0 · 设备身份（不许跳；全部不需要 root）

```sh
adb shell uname -r                      # 完整字符串，一个字符都不能差 → 文件名 / release 字段
adb shell cat /proc/version             # 构建标志（见陷阱 T3）+ clang 版本
adb shell getprop | grep -Ei 'ro.product.(model|device|name)|ro.board.platform|ro.build.(id|version.security_patch|fingerprint)'
adb shell cat /proc/sys/kernel/kptr_restrict   # 2 → /proc/kallsyms 全零，别指望它
adb shell ls -l /sys/kernel/btf/vmlinux        # 可读则可在真机侧交叉验证结构偏移
```

把这些原样写进本次适配记录。后面每个结论都要能回指到其中某一行。

**先查有没有现成的**：`app/src/main/assets/kernel_profiles/index.conf` 里搜 `uname -r`。
命中也不等于能用 —— 去阶段 3 的 C1 做厂商判别，这正是 vivo Fold5 踩的坑。

## 阶段 1 · 拿到本机镜像

优先级从高到低：

1. **官方完整 OTA / 固件包的 URL，直接喂给 extractor。** extractor 接受 `http(s)` URL，
   内部按 ZIP 中央目录 → OTA payload manifest → HTTP Range 只取 boot 分区所需片段。
   10 GiB 级 OTA 实测只读约 12 MB，不用整包下载。
2. 本地已下载的 OTA zip / `payload.bin` / `boot.img` / 裸 arm64 `Image`。
3. 高通机型另备 `xbl_config.img`（推 `kernel_phys_load`）；没有 FDT 内存图时用 `uefi.img`。
   联发科镜像通常两者都没有，靠 kallsyms `_text` 推，必要时 `--phys` 手动指定。

**必须记录**：OTA URL、包内 `boot` 目标分区哈希、重建出的 `boot.img` / `kernel.Image` 的
SHA-256。重建哈希与 manifest 目标哈希一致，才算"这确实是这台机器的镜像"。
第三方镜像站的包不可用于此步：一个被改过的镜像给出的偏移是错的，而错偏移的表现是内核内存被写坏。

## 阶段 2 · 生成候选 profile

```sh
(cd tools/extract_rs && cargo build --release)
B=build/extract/release/ghostlock-extract      # cargo target-dir 被重定向到仓库 build/

$B <image-or-url> --analysis                   # 先看：family / waiter layout / primitive / route 候选
$B <image-or-url> --format conf --out /tmp/candidate.conf
```

常用选项：`--xbl-config` / `--uefi` / `--phys`（物理载入地址）、`--kallsyms`（显式符号表，
省略则从镜像恢复内嵌表）、`--route`（覆盖建议 route）、`--no-disasm`（跳过反汇编推导）、
`--allow-missing`（把未解析符号当可选，输出 0 —— **仅用于诊断，不要进 profile**）。

`--analysis` 必须先跑：它给出 CVE 原语是否存在和 route 候选。原语不在就到此为止，别调参。

## 阶段 3 · 静态核对（offset 工作的真正内容）

extractor 跑通只是起点。下面四项逐项做，每项留证据。

### C1 · 厂商判别（同 `uname -r` 冲突检测）

把候选与内置同名 profile 逐键 diff，重点看安全相关符号：

```sh
diff <(sort /tmp/candidate.conf) <(sort app/src/main/assets/kernel_profiles/<uname-r>.conf)
```

关注 `offset.security_hook_heads`、`offset.selinux_blob_sizes`、`offset.selinux_enforcing`、
`offset.init_task`、`offset.init_cred`。
**任一不同 → 两台机器是不同的内核二进制**，必须独立 profile，不得复用、不得覆盖。

> 实例：vivo iQOO 12 与 X Fold5 都是 `6.1.145-android14-11-maybe-dirty`，
> `security_hook_heads` 相差 0x20（24047944 vs 24047976），`selinux_blob_sizes` 同样差 0x20。
> 用错那份照样能拿到 uid 0 —— 打偏的是安全相关写入，不是提权本身。

### C2 · 必填矩阵与边界

按 `PROFILE_SCHEMA.md` §3 核对所选 route 的必填字段全部非零且存在；跑一遍 §3 末尾的
credential 边界不等式（`cred.*`、`multicast_waiter` 的
`waiter_off + lock_offset + 8 ≤ buffer_size`、`cred.copy_size ≥ 0xa0`）。
**缺的字段整条省掉，不要写 0 或占位值。**

### C3 · 结构偏移对照 BTF

记录镜像 BTF 给出的 `task_struct.{pi_lock,pi_blocked_on,cred,seccomp,prio}`、
`rt_mutex_waiter.{task,lock}`，与 profile 里对应字段逐一对上。
真机 `/sys/kernel/btf/vmlinux` 可读时再交叉一遍 —— 这是唯一能证明"镜像就是在跑的那个内核"的独立来源。

### C4 · 符号地址 ≠ 结构成员偏移（最容易静默打偏的一类）

profile 里有两类数：**符号在镜像里的偏移**，和**成员在结构里的偏移**。native 负责相加，
profile 不能预先加好。典型：

- `offset.vr_sys_exit_tp` = `__tracepoint_sys_exit` 的**裸**符号偏移；
- `vr_guard.tracepoint_funcs` = BTF 里 `struct tracepoint.funcs` 的成员偏移（6.1 上为 0x40）；
- 实际目标由 native 算：`src/core/session/ancillary/vr_guard.hpp:43` 的
  `plan_vr_guard()` → `image_offset = vr_sys_exit_tp + tracepoint_funcs`。

所以手工往 `vr_sys_exit_tp` 里加 0x40 会**双加**，落到 `funcs` 之后的成员上。
反过来，`tracepoint_funcs` 缺失时 `plan_vr_guard()` 返回 `nullopt`，guard **fail-closed 静默不执行**。
两种错法的现象都是：**root 拿到了、KernelSU 也加载了，但 vr.ko 从未被中和，几分钟后 UI 冻死**。
这跟 exploit 不稳定长得一模一样，但不是一回事。

核对方式：确认 extractor 输出的这两个键各自独立存在；拿 `nm` / 反汇编查 `__tracepoint_sys_exit`
的裸地址，与 profile 值相等（不是相差 0x40）。

## 阶段 4 · 真机门禁

导入候选 profile（app 内导入 `.conf`，或 `./gradlew exportKernelProfiles` 出 GLK1 `.bin`
走 `--load-prebuilt-profile`）。条件：冷机、固定 CPU 对、单 route、KernelSU 未加载的干净启动。

每次运行记录：实际 `selected_cpus`、route、`prepare_kernel_page` 首次 attempt 数、
停在哪一行、结果、iomem 几何是否命中。日志在设备
`Download/ghostlock-debug-log/<时间>/*.log.txt`，同目录的 `profile.conf` / `profile.bin`
是本次真正生效的配置 —— **用它校验加载的就是你写的那份**，不要只看源文件。

### 怎么判读（别把预期行为当失败）

| 现象 | 含义 |
|---|---|
| `CMP_REQUEUE_PI ret=-1 errno=35` | `EDEADLK`，**流程预期**，不是失败判据 |
| disarm `errno=110` | `ETIMEDOUT`，同上 |
| 判成功 | `route_done status=0` + `success=1` + 写验证通过 + `KernelSU ready` |
| `child is root!` / `exploit complete` | 在 handoff **之前**打印，不能当终点（收早了会打断 ksu 加载） |
| 喷洒阶段中止 | 此时**尚无任何内核写入**，设备安全，秒级重试 |
| route 内卡死 | 整机僵住 → 看门狗复位，约 1 分钟 |

单次 PASS ≠ 稳定。同配置跑满约 15 次之前，成功率的变化都按噪声处理。

## 阶段 5 · 落库与归档

```sh
# 新增 <uname-r>.conf + index.conf 的 {release, file} 条目
jq . app/src/main/assets/kernel_profiles/index.conf
(cd tools/extract_rs && cargo test --release)
./gradlew :app:testDebugUnitTest :app:assembleDebug
```

门禁记录按 `docs/analysis/device-gates/*.md` 的格式归档，必须含：设备 / 固件 / 内核三元身份、
镜像与 profile 的 SHA-256、生效 `profile.conf` 快照、每轮运行表、结论与保留项。

**脱敏**：原始 dmesg 含 USB 序列号、已安装包名等环境信息，不整份公开；只放 stage 行与内核地址。

---

## 陷阱表

| # | 陷阱 | 怎么发现 | 处置 |
|---|---|---|---|
| T1 | 同 `uname -r` 不同厂商二进制 | C1 的符号 diff | 独立 profile；上游需要型号/固件身份参与匹配才能内置 |
| T2 | 符号偏移里预加了成员偏移（或成员偏移缺失） | C4 | 两键各自独立；缺则 fail-closed，现象是"root 成功但防护未中和" |
| T3 | `+pgo +bolt +lto` 构建 | 阶段 0 的 `/proc/version` | `select_stack` 栈几何静态不可达（上游 #112 `delta=-216`、#53），别试；6.1 上 TCP 几何经反汇编确认精确命中 |
| T4 | 硬改 `kernelsnitch.mm_struct_sz` | — | 不动（上游 #326：会把安全失败变成 kernel panic） |
| T5 | `--allow-missing` 的 0 进了 profile | 搜候选里的 `= 0` | 未解析符号被写成 0，看着像填好了。用不到的 route 字段整条省掉，不写 0 或占位值（`PROFILE_SCHEMA.md` §2） |
| T6 | 用第三方镜像站的包提取 | 阶段 1 的哈希链 | 只用能与 OTA manifest 目标哈希对上的镜像 |
| T7 | 只看源 conf、不看生效快照 | 对比设备上的 `profile.conf` | app 会补 `execution` 默认值；差异必须能逐项解释 |
| T8 | 非正常复位回滚设备侧日志 | 日志尾部出现 NUL / 内容回退 | f2fs checkpoint 行为；关键日志流到主机，别只存设备 |

## 交付物清单

- `<uname-r>.conf`（或独立导入 conf）+ `index.conf` 条目
- 阶段 0 身份记录、阶段 1 哈希链、阶段 3 四项核对证据
- 真机门禁记录（含生效 `profile.conf` 快照）
- 若发现 profile 选择冲突（T1）：写清冲突事实，不要靠覆盖文件绕过
