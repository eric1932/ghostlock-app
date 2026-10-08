# PD2436 profile 静态复核（vivo X Fold5，6.1.145）

2026-10-08。**纯静态复核，不含真机运行**，因此不进 `device-gates/`。
目的：用镜像自己的符号表验证 Fold5 自制 profile 的符号偏移，并定位 2026-10-05
「root 成功但随后冻屏」的真实成因。

## 来源与方法

证据来自设备持有者的固件提取归档 `static-20261003-firmware-and-analysis.zip`
里的 `new-16.1.17.12/vmlinux.elf`（由 `kernel.Image` 恢复、带符号表）。
内核 `6.1.145-android14-11-maybe-dirty`，clang 17.0.2，`+pgo +bolt +lto -mlgo`。

```sh
nm vmlinux.elf | grep -wE '_text|init_task|init_cred|empty_zero_page|root_task_group|selinux_blob_sizes|security_hook_heads|__tracepoint_sys_enter|__tracepoint_sys_exit'
# image_off = vaddr - _text
```

`_text = 0xffffffc008000000`。

## 符号偏移复核

| 符号 | ELF vaddr | image_off | profile 值 | 判定 |
|---|---|---|---|---|
| `init_task` | `0xffffffc00a1dfc00` | `0x21dfc00` | 35519488 | 一致 |
| `init_cred` | `0xffffffc00a1f24f0` | `0x21f24f0` | 35595504 | 一致 |
| `empty_zero_page` | `0xffffffc00a41b000` | `0x241b000` | 37859328 | 一致 |
| `root_task_group` | `0xffffffc00a422740` | `0x2422740` | 37889856 | 一致 |
| `selinux_blob_sizes` | `0xffffffc0096ef878` | `0x16ef878` | 24049784 | 一致 |
| `security_hook_heads` | `0xffffffc0096ef168` | `0x16ef168` | 24047976 | 一致 |
| `selinux_enforcing` | — | — | 39161664 | **未核**：不在该 ELF 符号表（疑为 local 符号） |

## `vr_sys_exit_tp` 结论

```
__tracepoint_sys_enter   image_off 0x23cb178
__tracepoint_sys_exit    image_off 0x23cb1c0     相距 0x48 = sizeof(struct tracepoint)
                                                 funcs 为末成员，位于 +0x40
```

`plan_vr_guard()`（`src/core/session/ancillary/vr_guard.hpp`）算出的写入目标
= `vr_sys_exit_tp + vr_guard.tracepoint_funcs` = `0x23cb1c0 + 0x40` = `0x23cb200`，
正是 `funcs` 指针字段。因此：

| profile | 值 | 判定 |
|---|---|---|
| `vr-fixed.conf`（实际使用） | 37532096 = `0x23cb1c0` | **正确** —— 就是裸符号偏移 |
| `validated.conf`（早期草稿，未使用） | 37532032 = `0x23cb180` | 比裸符号低 `0x40`，落在 **`sys_enter` 的 struct 内** |

`vr-fixed.conf` 注释写作 `0x23cb1c0 + 0x40`，描述的是「从草稿值 `0x23cb180` 加 `0x40`
得到 `0x23cb1c0`」这个修正动作，不是在裸符号上再加 `0x40`，**没有双加**。

这也给出 10-05 冻屏的成因：草稿值把 guard 的写入打到了 `sys_enter` 的结构里，
`vr.ko` 挂在 `sys_exit` 上的探针从未被中和。

## 可一般化的教训

`struct tracepoint` 步长 `0x48`、`funcs` 成员偏移 `0x40`，两者接近，使「差 0x40」
看上去像个合理候选值，而错误表现与 exploit 不稳定完全一样（都是 root 成功后冻屏）。
判据只能是与符号表**精确相等**。已写入
`.claude/skills/kernel-profile-port/SKILL.md` 的 C4 / C5。
