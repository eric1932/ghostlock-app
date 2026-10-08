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
adb pull /proc/config.gz                       # 常常是**唯一**可读的那个，见下
```

把这些原样写进本次适配记录。后面每个结论都要能回指到其中某一行。

**未 root 时实际能读到什么**（ASUS ROG 9 Pro 国行 / Android 16 实测，别预设能读）：

| 来源 | 结果 | 影响 |
|---|---|---|
| `uname -r` / `/proc/version` / `getprop` | 可读 | 身份核对照常做 |
| **`/proc/config.gz`** | **可读** | 见下，价值很高 |
| `/proc/sys/kernel/kptr_restrict` | denied | — |
| `/sys/kernel/btf/vmlinux` | denied | **C3 的设备侧交叉验证做不了**，改用阶段 3 的 `init_task` 语义自检 |
| `/proc/kallsyms` | denied | 符号只能从镜像恢复 |
| `/proc/iomem` | denied | **`kernel_phys_offset` 取不到**，见陷阱 T9 |
| `/proc/device-tree/*/reg`（含 `memory`） | denied（SELinux；目录能列，属性读不了） | 同上 |
| `/sys/kernel/notes`（GNU build-id） | denied | 内核二进制同一性只能靠别的证据 |

`/proc/config.gz` 为什么值钱：`CONFIG_IKCONFIG` 把**同一份** config 既以它暴露，
也以 gzip 块嵌在镜像的 `IKCFG_ST`…`IKCFG_ED` 之间。所以它能做两件别处做不到的事：

1. **证明"跑的内核就是这个镜像的构建"**（设备固件版本与手上 OTA 不一致时的救命证据，见阶段 1）；
2. **判定依赖 kconfig 的字段语义**。典型：`offset.selinux_enforcing` 取的是 `selinux_state`
   的符号偏移，而 `enforcing` 只在 `CONFIG_SECURITY_SELINUX_DEVELOP=y` 时才存在、
   才是第一个成员；`CONFIG_RANDSTRUCT_FULL=y` 还会打乱 `__randomize_layout` 结构的布局。
   两条都不查就等于在赌。

```sh
adb pull /proc/config.gz && gunzip -c config.gz > device.config
grep -E 'CONFIG_SECURITY_SELINUX_DEVELOP|CONFIG_RANDSTRUCT|CONFIG_RANDOMIZE_BASE|CONFIG_EFI_STUB|CONFIG_RELOCATABLE|CONFIG_ARM64_(4K|16K)_PAGES' device.config
```

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

### 怎么拿到官方直链

厂商专用的只有「查到 URL」这一步：各家一个下载中心 / OTA 接口，抓一次包就能脚本化
（注意国行站常是独立域名和独立的产品 ID 空间，别拿全球站的 ID 去查）。

**拿到 URL 之后不必重写提取逻辑** —— ZIP 中央目录 → payload manifest → Range 只取
boot 分区，extractor 已内置。只有需要留提取证据（manifest、分区哈希、实际下载字节数）
时才单独跑提取脚本。

**必须记录**：OTA URL、包内 `boot` 目标分区哈希、重建出的 `boot.img` / `kernel.Image` 的
SHA-256。重建哈希与 manifest 目标哈希一致，才算"这确实是这台机器的镜像"。
第三方镜像站的包不可用于此步：一个被改过的镜像给出的偏移是错的，而错偏移的表现是内核内存被写坏。

### 设备固件版本 ≠ 能下到的 OTA 版本（很常见）

厂商下载中心通常**只挂最新一版**，而用户常因为怕漏洞被修而停在旧版。此时 `uname -r`
往往仍然相同（厂商只动 userspace / 安全补丁标注，没重编内核），于是 profile 会被选中，
踩的正是不变量 1。

不要就这么跑，也不要为了对齐而让用户升级（升级可能真把原语修掉）。先论证内核二进制同一：

```sh
adb pull /proc/config.gz && gunzip -c config.gz > device.config
# 镜像内嵌的同一份 config：IKCFG_ST…IKCFG_ED 之间的 gzip 块
python3 -I - kernel.Image image.config <<'EOF'
import sys, gzip
img = open(sys.argv[1],'rb').read()
st, ed = img.find(b'IKCFG_ST'), img.find(b'IKCFG_ED')
open(sys.argv[2],'wb').write(gzip.decompress(img[st+8:ed]))
EOF
cmp device.config image.config && echo IDENTICAL
```

config 逐字节相同 + `uname -r` + `/proc/version` 的构建时间戳 + GKI `ab` 号四项全同，
才可以继续，并在记录里写明这是**强证据而非证明**（config 只是构建输入的一个子集）。
真正的证明需要哈希设备自己的 `boot` 分区（要 root）。

> 实例：ROG 9 Pro 国行设备在 `36.0810.1810.84`（补丁 2026-05-01），官方只剩
> `.86`（补丁 2026-08-05），`.84` 的包 CDN 已 404。两者 `uname -r`、构建时间戳
> `Fri May 22 09:40:40 UTC 2026`、`ab15480978` 与 config（211 778 B）全部相同 ——
> ASUS 只改了 userspace 的补丁标注，没重编内核。这也解释了为什么 `.86` 里原语还在。

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

三种错法，现象完全一样：**root 拿到了、KernelSU 也加载了，但 vr.ko 从未被中和，
几分钟后 UI 冻死**。这跟 exploit 不稳定长得一模一样，但不是一回事。

| 错法 | 后果 |
|---|---|
| 往 `vr_sys_exit_tp` 预加了 `funcs` 偏移 | 双加，落到 `struct tracepoint` 之外 |
| `tracepoint_funcs` 缺失 | `plan_vr_guard()` 返回 `nullopt`，guard fail-closed 静默不执行 |
| 符号本身取偏了 | 写进**邻居 tracepoint** 的结构里 |

第三种最阴，因为"差一点"看着很合理。PD2436（6.1.145）实测：

```
__tracepoint_sys_enter  image off 0x23cb178
__tracepoint_sys_exit   image off 0x23cb1c0    # 相距 0x48 = sizeof(struct tracepoint)
                                               # funcs 是最后一个成员，位于 +0x40
native 实际写入       = 0x23cb1c0 + 0x40 = 0x23cb200
```

所以 `vr_sys_exit_tp` 写成 `0x23cb180` 只比正确值低 0x40，但那个地址落在
**sys_enter 的 struct 里**，guard 写了也白写。`0x48` 的结构步长 + `0x40` 的成员偏移
正好让"差 0x40"显得像个合理的候选值 —— 不要靠眼力，要靠符号表精确相等。

### C5 · 用符号表把每个 `offset.*` 重算一遍

手改过或导入来的 profile 必须过这一步（C1 的 diff 只能和另一份内置比，比不出手改的错）。
拿这台机器自己的 `vmlinux` / 恢复出的 ELF：

```sh
nm vmlinux.elf | grep -wE '_text|init_task|init_cred|empty_zero_page|root_task_group|selinux_blob_sizes|security_hook_heads|__tracepoint_sys_exit'
```

对每个符号算 `image_off = vaddr - _text`，要求与 profile 里的值**精确相等**，不接受"接近"。
符号表里查不到的（如 `selinux_enforcing` 常是 local 符号）另途核对，不要跳过。

## 阶段 4 · 真机门禁

导入候选 profile（app 内导入 `.conf`，或 `./gradlew exportKernelProfiles` 出 GLK1 `.bin`
走 `--load-prebuilt-profile`）。条件：冷机、固定 CPU 对、单 route、KernelSU 未加载的干净启动。

每次运行记录：实际 `selected_cpus`、route、`prepare_kernel_page` 首次 attempt 数、
停在哪一行、结果、iomem 几何是否命中。日志在设备
`Download/ghostlock-debug-log/<时间>/*.log.txt`，同目录的 `profile.conf` / `profile.bin`
是本次真正生效的配置 —— **用它校验加载的就是你写的那份**，不要只看源文件。

### 两个不在 profile 里、但决定成败的变量

静态核对（阶段 3）管的是"配置对不对"。阶段 4 失败时，**先怀疑这两个，它们和配置正确性无关**：

| 变量 | 实测影响（ROG 9 Pro `6.6.127`，同一份 conf） |
|---|---|
| **CPU 对** | cpu4/5（3.53 GHz 簇）：W1 的字节**永不落地**，15/15 失败，另一次运行直接 kernel panic。cpu6/7（两颗 4.32 GHz 超大核）：W1/W2 都过，2/2 成功 |
| **是否冷机** | 同样 cpu6/7：冷机（uptime 54 s）6 次 route **0 次** `prepare_kernel_page` 重试、23 s 完成、KernelSnitch 泄漏失败 **0 次**；开机 36 分钟后 **18 次**重试、60 s、泄漏失败 **15 次** |

所以：**冷机不是形式要求，是有实测数据的性能开关**；每次门禁前重启，别省。
而 CPU 对是 app 按 CPU 簇自动配对给的默认值，**默认那对可能根本不可用**。

**门禁找到可用的那一对之后，把它写进 profile**，否则下一个人（包括三个月后的你）
还会从那个会 panic 的默认值开始：

```hocon
execution {
  recommended_cpus {
    main = 6
    consumer = 7
  }
}
```

用户在首页手选的 `selected_cpus` 仍然优先于它；`app/src/main/assets/kernel_profiles/`
里 `5.15.167-…` 和 `6.1.145-…` 两份都带这一项，注释写明了同样的理由。
手选会存进 SharedPreferences，**是粘着的** —— 下次运行还是上次那对，核对日志里的
`cpu pair:` 行，别凭记忆。

### 怎么判读（别把预期行为当失败）

| 现象 | 含义 |
|---|---|
| `CMP_REQUEUE_PI ret=-1 errno=35` | `EDEADLK`，**流程预期**，不是失败判据 |
| disarm `errno=110` | `ETIMEDOUT`，同上 |
| 判成功 | `route_done status=0` + `success=1` + 写验证通过 + `KernelSU ready` |
| `child is root!` / `exploit complete` | 在 handoff **之前**打印，不能当终点（收早了会打断 ksu 加载） |
| 喷洒阶段中止 | 此时**尚无任何内核写入**，设备安全，秒级重试 |
| route 内卡死 | 整机僵住 → 看门狗复位，约 1 分钟 |
| **`prepare_kernel_page` 每次都 `ok attempt=1`，但写从不落地** | **假成功签名** —— 堆准备锁到了错的页。先换 CPU 对，见下 |
| `prepare_kernel_page` 大量 `retry n/4`、偶尔耗尽，但落地了 | 正常（非冷机的典型样子）。不是配置问题 |
| `KernelSnitch mm_struct leak failed` 反复出现 | 同上，冷机下归零。**不要**去填 `kernelsnitch.mm_struct_sz`（陷阱 T4） |
| **`route_done success=1` 却 `W1: SELinux attempt N/N` 全败** | **原语可用但写偏了**，见下 |

#### `route` 成功而 `W1` 失败 —— 先分清竞态还是地址错

```
prepare_kernel_page ok attempt=1
route_done status=0 clean=1/1 step=0 errno=0 calls=1 success=1    ← route 自报成功
W1: SELinux attempt 15/15
[-] Write 1 failed
```

**先搞清 W1 是怎么验的，否则会把竞态误判成地址错。**
W1 写 `selinux_state.enforcing := 0`，验证是 `attack::check_selinux_off()`
（`attack/ops.hpp`）：它 `open("/sys/fs/selinux/enforce")`，**打不开就返回 0**。
enforcing 状态下 `untrusted_app` 被 SELinux 拦住读不到这个文件，所以
"**能打开**"本身就是写落地的证明 —— 这个判据是可靠的，不存在"写对了但验错了"。

反过来说，失败只说明那一次没写进去，**不说明地址错**。

**第一步永远是：同一次开机里再跑一遍。**
`attempt N/N` 全败看着像稳定失败，其实不是 —— 15 次尝试共用同一次喷洒出来的页，
那一次布局不对就会 15 次全废。实测：ROG 9 Pro 用**同一份 conf**、**同一次开机**
（`uptime` 16003 s 与 16278 s，相隔 275 s）跑两次，第一次 W1 15/15 全败，
第二次 W1 一次就过。

> 这一条同时是最强的地址排除法：**同一次开机里地址是常量**。
> 若 `kernel_phys_load` / `phys_offset` / 字段语义任一项错，W1 在这次开机里**永远**
> 不可能通过。只要见过一次通过，整类地址假设（含 EFI stub 物理 KASLR）当场出局，
> 不必再去读 iomem、算物理基址。**先花 3 分钟重跑，别花 3 小时算地址。**

**第二步：换另一簇的 CPU 对。** 这是实测里真正的判别量。
ROG 9 Pro 上 cpu4/5 与 cpu6/7 的差别是：

| | cpu4/5（3.53 GHz 簇） | cpu6/7（4.32 GHz 超大核） |
|---|---|---|
| `prepare_kernel_page` | **15/15 全是 `ok attempt=1`** | 大量 retry，偶尔耗尽 |
| `route_done` | `success=1`（15 次） | `success=1` |
| W1 的字节是否落地 | **从不** | 落地 |

4/5 上堆准备"一次就成"却永远写不进去；6/7 上堆准备很费劲但写是真的。
**"每次都一次就成"反而是坏信号** —— 它说明 `prepare_kernel_page` 在误报，
锁到的不是我们要的页。同一台机器上这也解释了另一次运行的 kernel panic：
往错页写一个指针就是现成的 panic 源。

> 怎么换：app 首页的 CPU 选择器。优先试**另一个频率簇**的相邻一对
> （`/sys/devices/system/cpu/cpu*/cpufreq/cpuinfo_max_freq` 看簇边界）。
> 找到可用的那一对后写进 profile 的 `execution.recommended_cpus`（见本阶段开头）。

只有在**换过 CPU 对、跨多次冷机**都卡在 W1 时，才按下面顺序查地址，每步都留证据：

1. **把地址链路算一遍，和日志里的 `target=` 对比。**
   `address_space.cpp` 的 `data_alias_checked()`：
   `physical = kernel_phys_load + (image_addr − KIMAGE_TEXT_BASE)`，
   `direct = (physical − phys_offset) | P0_PAGE_OFFSET`。
   先确认 `KIMAGE_TEXT_BASE`（`target_constants.hpp`，当前 `0xffffffc080000000`）
   **等于本镜像的 `_text`** —— 不等就是整类偏移全错。
2. **`phys_offset` 从哪来**：profile 的 `kernel_phys_offset`，缺失则用编译默认
   `P0_PHYS_OFFSET`。别猜，跑 `scripts/xbl_memory_map.py`（见下）。
3. **字段语义对不对**：`selinux_enforcing` 依赖 `CONFIG_SECURITY_SELINUX_DEVELOP`
   与 `CONFIG_RANDSTRUCT`，查 `/proc/config.gz`（阶段 0）。
4. **`success=1` 到底证明了什么**：ANC-02 记「`ROUTE_OK` 只由 consumer 的验证写入决定」。
   若那个验证写的是 scratch 位置而非本次 target，则它只证明原语可用，**不**证明 target 落地。
5. 以上全对还失败 → 怀疑**内核物理落点与 `kernel_phys_load` 不一致**（陷阱 T9 的第二半）。

#### W1 过了，之后黑屏 / 整机复位 —— 换一类问题

W1 一旦通过，地址链路和字段语义就都被证明了，**后面的失败是别的原因**。
先确认是 panic 还是卡死：

```sh
adb shell getprop ro.boot.bootreason          # kernel_panic / reboot,...
adb shell getprop persist.sys.boot.reason.history   # 带 epoch，能和日志对时刻
```

`kernel_panic` 说明内核主动崩了（不是看门狗静默卡死）。

**先排除 CPU 对**：如果同一配置也出现过"W1 全败"，那 panic 和 W1 失败很可能是**同一个
根因** —— 堆准备误报成功、写落在随机物理页，运气不同就分别表现为"没反应"和"崩机"。
ROG 9 Pro 就是这样：cpu4/5 一次 W1 全败、一次 panic；换 6/7 后两种都消失。
**先换 CPU 对重跑，再往下查。**

CPU 对换过仍 panic，才查 **W1 之后到崩之前**那几步都写了什么。W1 之后依次是：W1b（scratch / resident 修复）→ 任务发现
（打印 `child_task=0x…`）→ W2b（vr.ko tag 清除，见 T12）→ W2a（`cred := init_cred`）。
这几步里 W1b 和 W2b 都带**盲写**，且 W2 的 target 依赖任务发现的结果 —— 任务发现
找错了 task，W2 就是往随机内核地址写一个指针，panic 完全合理。

要定位到具体哪一行，**必须有本次运行的 trace**，而 panic 会把设备上那份连目录一起
抹掉（T8）—— 所以这类运行**一定要先挂上 `gate_watch.sh`** 再点运行。

单次 PASS ≠ 稳定。同配置跑满约 15 次之前，成功率的变化都按噪声处理。

## 阶段 5 · 落库与归档

```sh
# 新增 <uname-r>.conf + index.conf 的 {release, file} 条目
jq . app/src/main/assets/kernel_profiles/index.conf
(cd tools/extract_rs && cargo test --release)
./gradlew :app:testDebugUnitTest :app:assembleDebug
```

落库前再确认三件事：

1. **profile 带上了门禁验证过的 `execution.recommended_cpus`**（陷阱 T13）。
   没有这一项的 profile 等于把别人推到 app 的默认 CPU 对上，那一对可能会 panic。
2. **成功率跑满**（同配置约 15 次）。单次 PASS 不够。
3. 文件头的 `UNVERIFIED CANDIDATE` 字样换成门禁结论。

门禁记录按 `docs/analysis/device-gates/*.md` 的格式归档，必须含：设备 / 固件 / 内核三元身份、
镜像与 profile 的 SHA-256、生效 `profile.conf` 快照、每轮运行表、结论与保留项。
**失败的运行也要写**，而且要写清是怎么被排除的 —— 门禁记录的价值一半在失败那几行。

**脱敏**：原始 dmesg 含 USB 序列号、已安装包名等环境信息，不整份公开；只放 stage 行与内核地址。

---

## 陷阱表

| # | 陷阱 | 怎么发现 | 处置 |
|---|---|---|---|
| T1 | 同 `uname -r` 不同厂商二进制 | C1 的符号 diff | 独立 profile；上游需要型号/固件身份参与匹配才能内置 |
| T2 | 符号偏移里预加了成员偏移（或成员偏移缺失） | C4 | 两键各自独立；缺则 fail-closed，现象是"root 成功但防护未中和" |
| T3 | `+pgo +bolt +lto` 构建 | 阶段 0 的 `/proc/version` | **先跑 `--analysis` 看 `pselect chain` 有没有 derived，不要据此直接放弃 `select_stack`。** 上游 #112（`delta=-216`）/#53 是在**那些具体内核**上静态不可达；6.6 实测相反 —— ROG 9 Pro 的 `6.6.127`（`+pgo +bolt +lto +mlgo`）推出了 `shift=-2`，且仓库 24 份 6.6.x profile 全部用 `select_stack` 且 `waiter_shift` 全为 `-2`。6.1 上 TCP 几何经反汇编确认精确命中 |
| T4 | 硬改 `kernelsnitch.mm_struct_sz` | — | 不动（上游 #326：会把安全失败变成 kernel panic） |
| T5 | `--allow-missing` 的 0 进了 profile | 搜候选里的 `= 0` | 未解析符号被写成 0，看着像填好了。用不到的 route 字段整条省掉，不写 0 或占位值（`PROFILE_SCHEMA.md` §2） |
| T6 | 用第三方镜像站的包提取 | 阶段 1 的哈希链 | 只用能与 OTA manifest 目标哈希对上的镜像 |
| T7 | 只看源 conf、不看生效快照 | 对比设备上的 `profile.conf` | app 会补 `execution` 默认值；差异必须能逐项解释 |
| T8 | **panic / 复位会让本次运行的 trace 整份消失，而 `logcat` 里根本没有 trace** | panic 之后 `adb pull ghostlock-debug-log` 回来只有**上一次**的目录，本次那个时间戳目录不存在；`grep prepare_kernel_page logcat.log` 为 0 行 | 两件事都要知道：①**exploit 的 trace 不进 logcat**。app 的 `<k>` 行和 native 的 `[spray]` / `prepare_kernel_page` / `=== W1` 只写进 app 自己的 `ghostlock-debug-log/<时间戳>/*.log.txt`，logcat 里关于 ghostlock 只有 auditd 的 avc 回显 —— 光抓 logcat 等于什么都没抓。②那个文件**每行 flush 但不 fsync**（`DebugAttackLog.append`）且经 MediaStore 创建，panic 后 f2fs 回滚到上一个 checkpoint，**连目录一起没了**（实测：panic 那次一个字节都没留下）。<br>所以必须在设备还活着时就把它轮询快照到主机：`scripts/gate_watch.sh` 现在同时抓两路（logcat 抓 panic / avc / 掉线时刻，快照器抓 trace），并且只在快照变长时替换、换新运行目录时重置基线。logcat 仍要抓 —— 它是唯一能看到内核 panic 行和复位时刻的那一路。<br>**别指望 pstore 兜底**：实测这台机器 `/sys/fs/pstore` 对 shell 不可读，而 app 成功后自己 dump 出来的 `pstore/` 目录是**空的**（没有可读的 ramoops），所以 panic 那次连内核侧现场都没有。主机侧快照是唯一的记录 |
| T9 | `kernel_phys_offset` 缺失 → 悄悄用编译默认 `P0_PHYS_OFFSET`（`0x80000000`） | `address_space.cpp:86`；日志里的 `target=` 反推 | 未 root 时 `/proc/iomem` 和 `/proc/device-tree/*/reg` 都读不到，**但不要猜也不要照抄别家 profile**：跑 `scripts/xbl_memory_map.py <xbl_config.img>` 把 bootloader 的整张内存图读出来。最低区段基址就是 `kernel_phys_offset` 候选，同时能独立印证 `kernel_phys_load`。<br>注意**两件不同的事**：①`phys_offset`（DRAM 基址）对不对；②`kernel_phys_load` 是否等于内核**实际运行**的物理基址 —— `CONFIG_RANDOMIZE_BASE=y` + `CONFIG_EFI_STUB=y`（高通 XBL 即 UEFI）下 EFI stub 可能把 Image 搬到随机物理地址，那时 bootloader 的静态保留区**不是**运行地址。②目前只有 root 后的 `/proc/iomem`（`--iomem <dump>`，看 `Kernel code` 起始）能判 |
| T10 | app 与 extractor 不同分支 → profile 被判 `unknown top-level key` | app 报"配置需要修正"，而几何字段其实都在 | 两者必须来自**同一分支**。实例：vr.ko 中和（`recommend_vr_guard` / `vr_guard`）只在上游 `vr-ko-bypass-dev`，官方 `pre-release` 的 APK 是从 `main` 构建的，`ProfileResolver.KnownTopLevel` 里没有这两个键 → `validateMerged` 报错拦住运行。要么用同分支自建 APK（CI `workflow_dispatch` 即可，不必本地装 SDK/NDK），要么另存一份去掉该段的变体 conf |
| T11 | 把编辑器显示的 `null` 行当成"必须填的错误" | 对照 `ProfileResolver` 的 `RequiredTopLevel` / `RequiredTaskStruct` / `RequiredCred` / `RequiredOffset` 四张清单 | app 会把 profile **未携带**的字段渲染成可编辑的 `null` 行（`AndroidProfileConfigController` 里 `completeProfileFields` 的注释写明了）。`kernel_phys_offset`、`kernelsnitch.mm_struct_sz`、`cred.usage_offset`、`cred.refN_*` 都属于这一类 —— **不在必填清单里，填进去反而写入错值**。真正被拦住的只看日志的 `invalid=` 和红色标记 |
| T12 | vr.ko tag 清除那段会在 `/proc/modules` 读不到时**默认"假设已加载"**，然后按 vivo 6.1 推出来的偏移对子任务做两次盲写 | 日志有没有 `vr.ko not loaded; skipping tag clear`；`adb shell cat /proc/modules \| awk '{print $1}' \| grep -i '^vr'` | `cve_2026_43499_backend.cpp` 的 W2b：`vr_needed` 在 `fopen("/proc/modules")` 失败时**取 1**，接着零写 `child_task+0x00`（thread_info.flags）和 `(child_task+VR_TAG_B_OFF)&~7`（默认 `0x2c`→对齐到 `0x28`）。这两个偏移来自**已验证的 vivo 6.1 树**，源码注释自己写着「VERIFY ON-DEVICE」。非 vivo 的 6.6 上 `task_struct+0x28..0x2f` 是什么完全没保证，盲零写是现成的 panic 源。<br>好消息是这段排在 W1 之后，W1 成功后 SELinux 已 permissive，`/proc/modules` 读得到 → 没有 `vr`/`vr_` 前缀模块时 `vr_needed=0` 整段跳过。所以**先确认日志里有 `not loaded; skipping`**；若该行缺失或显示 `loaded`，而设备又不是 vivo，就是在无谓地冒 panic 风险 |
| T13 | profile 不带 `execution.recommended_cpus` → app 用按簇自动配对的默认值，而**默认那对可能根本不可用** | 日志的 `cpu pair: main=N consumer=M` 和你以为的不一样；或者门禁一直过不去而换 CPU 对就好了 | 门禁验证出可用的那一对之后**写进 profile**。实例：ROG 9 Pro 的默认 4/5 会让 W1 永不落地并曾导致 kernel panic，6/7 才可用；conf 里不写这一项，等于把下一个人推到会 panic 的那条路上。注意 app 把 `recommended_cpus` 当"默认选中项"而非强制值，用户手选的 `selected_cpus` 仍然优先，而且手选**会存进 SharedPreferences 粘住** —— 每次都核对日志里的 `cpu pair:` 行，别凭记忆 |
| T14 | 多台设备（或一台走 USB + 无线两路）同时连着，`adb` 命令打到了错的那台 | 读出来的 `uname -r` / 文件路径莫名其妙对不上 | 所有 `adb` 都带 `-s <序列号>`。`gate_watch.sh` 会在检测到多于一台在线时直接拒绝运行并列出设备，用 `GL_SERIAL=` 指定。不变量 1（`uname -r` 逐字符核对）是最后一道防线，实测确实拦住过一次 |

## 随带脚本

两个都在 `scripts/`，只读、不需要 root、不驱动 exploit。

### `xbl_memory_map.py` — 取 `kernel_phys_offset` 候选（高通）

```sh
python3 -I scripts/xbl_memory_map.py rog9_xbl/xbl_config.img
```

把 xbl_config 里**所有**内嵌 FDT 的 `memorymap` 节点读出来（extractor 的 `fdt.rs` 解析
同一张表，但只返回 Kernel 行）。输出整张表 + 最低区段基址（`kernel_phys_offset` 候选）
+ Kernel 行（交叉印证 `kernel_phys_load`）。

这是未 root 时唯一的静态来源：`/proc/iomem` 要 root，`/proc/device-tree/*/reg`
被 SELinux 挡住。**但最低基址只是候选** —— Linux 的 `PHYS_OFFSET` 取自它自己 DT
`/memory` 节点的第一个 memblock，不一定是 bootloader 列出的最低行。标注为候选，
拿到 root 后用 `ghostlock-extract --iomem <dump>` 确认。

### `gate_watch.sh` — 阶段 4 的主机侧记录器（app 流程）

```sh
GL_CONF=~/path/<uname-r>.conf bash scripts/gate_watch.sh cold-boot-1
GL_SERIAL=<序列号>                 # 多台设备连着时必须给，否则脚本拒绝运行
GL_OUT_ROOT=<目录> GL_POLL_SEC=0.5 # 可选
```

**先起脚本，再点运行。** 反过来也还能救（快照器无条件跟最新的 run 目录），
但收尾时要核一眼它打印的 trace 来源时间戳是不是本次。

只读前置检查（从 conf 的 `release` 字段取期望 `uname -r` 并逐字符核对、conf 哈希本地 vs 设备、
管理器 app 是否在位、KernelSU 是否已加载、启动时长是否像冷机、上次启动原因是否 `kernel_panic`）
→ 挂**两路**记录 → 设备复位自动重连 → Ctrl-C 收尾时拉设备侧 `ghostlock-debug-log/`、
diff 生效 `profile.conf`（陷阱 T7）、打印关键行摘要与 trace 末尾、再打印 logcat 里的内核
panic / oops / 看门狗行。

两路分别是（为什么必须两路见陷阱 T8）：

| 落盘文件 | 内容 | 为什么需要 |
|---|---|---|
| `device-trace.log` | **exploit 的全部输出**（`<k>` / `[spray]` / `prepare_kernel_page` / `=== W1` …） | 这些**只**写进设备上的 `ghostlock-debug-log/<时间戳>/*.log.txt`，而 panic 后 f2fs 会把那个目录整份回滚掉。脚本按 `GL_POLL_SEC`（默认 0.5 s）轮询快照，只在变长时替换，设备侧回滚伤不到主机这份 |
| `logcat.log` | 内核 panic / oops / 看门狗、auditd 的 avc denied、掉线与重连时刻 | 这一路**没有** exploit 的任何输出，但 panic 行和复位时刻只在这里 |

跑之前它会打印被忽略的基线路径（上一次运行的 trace），点运行后新目录一出现就开始收并增量打印。

CLI 流程（`--load-prebuilt-profile`）不要用它：那边脚本是父进程，可以在
`prepare_kernel_page retry` 处就地 abort 重摇；app 流程里控制权不在脚本手里。
**两个流程的 uid / seccomp / W3 都不同，成功率不能互比。**

## 交付物清单

- `<uname-r>.conf`（或独立导入 conf）+ `index.conf` 条目
- 阶段 0 身份记录、阶段 1 哈希链、阶段 3 四项核对证据
- 真机门禁记录（含生效 `profile.conf` 快照）
- 若发现 profile 选择冲突（T1）：写清冲突事实，不要靠覆盖文件绕过
