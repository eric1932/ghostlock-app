#!/usr/bin/env bash
# gate_watch.sh — 阶段 4 真机门禁的主机侧记录器（app 流程）。
#
#   GL_CONF=~/Downloads/<uname-r>.conf bash gate_watch.sh [标签]
#
# 这个脚本不驱动 exploit，只负责记录：你在 app 里导入 conf、点运行，它在主机上把
# logcat 实时落盘，设备卡死复位也不会丢。跑完按 Ctrl-C 收尾。
#
# CLI 流程（`--load-prebuilt-profile`）请另写驱动脚本：那边脚本是父进程，能在
# `prepare_kernel_page retry` 处就地 abort 重摇；app 流程里控制权不在脚本手里。
# 两个流程的 uid / seccomp / W3 都不同，成功率不能互比。
#
# ── 为什么必须流到主机（陷阱 T8）────────────────────────────────
# route 里卡死会触发看门狗复位，f2fs 的 checkpoint 行为会把设备侧日志回滚
# （尾部出现 NUL 或内容倒退）。主机侧的流不受影响，是唯一可靠的那一份。
#
# ── 落盘纪律，别改回去 ─────────────────────────────────────────
# adb 的 stdin 必须接 /dev/null。adb 若落在后台进程组里又去动控制终端
# (tcsetattr) 会吃 SIGTTOU 被挂起 —— 命令已经发给设备、exploit 照跑、设备照卡，
# 但 adb 不读不写，**日志 0 字节**。所以：不用 set -m、不套子 shell，并且下面
# 有预检，先用无害命令确认流式输出真的在涨，再让你去点运行。
# ──────────────────────────────────────────────────────────────
set -u

PKG=${GL_PKG:-com.ghostlock.app}
CONF_LOCAL=${GL_CONF:?用法: GL_CONF=<本地 .conf 路径> bash $0 [标签]}
CONF_NAME=$(basename "$CONF_LOCAL")
CONF_DEV=${GL_CONF_DEV:-/sdcard/Download/$CONF_NAME}

TS=$(date +%Y%m%d-%H%M%S)
LABEL=$(printf '%s' "${1:-}" | tr -cs 'A-Za-z0-9._-' '-' | sed 's/^-*//; s/-*$//')
OUT=${GL_OUT_ROOT:-$HOME/Downloads/gate-logs}/$TS${LABEL:+-$LABEL}
mkdir -p "$OUT"
LOGCAT="$OUT/logcat.log"

say() { printf '%s\n' "$*"; }
hr()  { printf '%s\n' "────────────────────────────────────────────────────────"; }

command -v adb >/dev/null || { say "需要 adb"; exit 1; }
[ -r "$CONF_LOCAL" ] || { say "读不到 $CONF_LOCAL"; exit 1; }

# profile 的 release 字段就是必须匹配的 uname -r
EXPECT_UNAME=$(sed -nE 's/^[[:space:]]*release[[:space:]]*=[[:space:]]*"?([^"]+)"?.*/\1/p' "$CONF_LOCAL" | head -1)
EXPECT_SHA=$(shasum -a 256 "$CONF_LOCAL" | awk '{print $1}')

hr; say "1. 前置检查（全部只读）"
adb wait-for-device
UNAME=$(adb shell uname -r 2>/dev/null | tr -d '\r')
say "   uname -r      : $UNAME"
say "   profile release: $EXPECT_UNAME"
if [ -z "$EXPECT_UNAME" ] || [ "$UNAME" != "$EXPECT_UNAME" ]; then
  say "   ✗ 不一致（不变量 1）。停。"; exit 1
fi
say "   ✓ 逐字符一致"

GOT_SHA=$(adb shell "sha256sum '$CONF_DEV' 2>/dev/null" | awk '{print $1}' | tr -d '\r')
if [ "$GOT_SHA" != "$EXPECT_SHA" ]; then
  say "   ✗ 设备上的 conf 哈希不对或文件不在：${GOT_SHA:-<缺失>}"
  say "     adb push '$CONF_LOCAL' /sdcard/Download/"; exit 1
fi
say "   ✓ 设备 conf 哈希 = 本地 (${EXPECT_SHA:0:12}…)"

adb shell "pm list packages" 2>/dev/null | grep -q "^package:$PKG\$" \
  || { say "   ✗ $PKG 没装"; exit 1; }
say "   ✓ $PKG $(adb shell "dumpsys package $PKG | grep -m1 versionName" 2>/dev/null | tr -d ' \r')"

# ksud 来自管理器 app 的 nativeLibraryDir；缺了 W1/W2 仍能拿 uid 0 但不会加载模块
MGR=$(adb shell "pm list packages" 2>/dev/null | grep -oE 'me\.weishu\.kernelsu(\.pr)?|com\.resukisu\.resukisu|com\.kowx712\.supermanager' | head -1)
[ -n "$MGR" ] && say "   ✓ 管理器 $MGR（提供 ksud）" \
              || say "   ⚠ 没有 KernelSU/ReSukiSU/KowSU —— 不会加载模块，门禁到不了 KernelSU ready"

adb shell "cat /proc/modules 2>/dev/null" | grep -qi kernelsu \
  && say "   ⚠ KernelSU 已加载 —— 不是干净启动，先重启" \
  || say "   ✓ KernelSU 未加载"
UP=$(adb shell "cat /proc/uptime" 2>/dev/null | awk '{printf "%d",$1}')
say "   启动时长      : ${UP}s$([ "${UP:-0}" -gt 1800 ] && echo '   ⚠ 不是冷机')"

{ say "uname=$UNAME"; say "conf=$CONF_NAME"; say "conf_sha256=$GOT_SHA"
  say "manager=${MGR:-none}"; say "uptime_at_start=${UP}s"
  adb shell getprop ro.build.fingerprint 2>/dev/null | tr -d '\r' | sed 's/^/fingerprint=/'
  say "host_start=$(date -Iseconds)"; } > "$OUT/identity.txt"

hr; say "2. 挂 logcat 到主机（设备复位自动重连）"
adb logcat -c 2>/dev/null || true
stream() {
  while :; do
    adb wait-for-device
    printf '\n===== logcat attached %s =====\n' "$(date -Iseconds)" >> "$LOGCAT"
    adb logcat -b all -v threadtime '*:V' >> "$LOGCAT" 2>&1 < /dev/null
    printf '\n===== logcat detached %s (设备掉线/复位?) =====\n' "$(date -Iseconds)" >> "$LOGCAT"
    sleep 1
  done
}
stream &
STREAM_PID=$!

sleep 2; adb shell log -t GLGATE "stream preflight $TS" >/dev/null 2>&1; sleep 2
if grep -q "stream preflight $TS" "$LOGCAT" 2>/dev/null; then
  say "   ✓ 预检通过，流式输出确认在落盘"
else
  say "   ✗ 预检失败：标记没出现（日志 $(wc -c < "$LOGCAT" | tr -d ' ') 字节）。别继续，先修流。"
  kill "$STREAM_PID" 2>/dev/null; exit 1
fi

cleanup() {
  trap - INT TERM
  hr; say "3. 收尾"
  kill "$STREAM_PID" 2>/dev/null; wait "$STREAM_PID" 2>/dev/null
  adb wait-for-device
  adb pull /sdcard/Download/ghostlock-debug-log "$OUT/device-debug-log" >/dev/null 2>&1 \
    && say "   ✓ $OUT/device-debug-log" || say "   （设备上没有 ghostlock-debug-log）"

  EFF=$(find "$OUT/device-debug-log" -name 'profile.conf' 2>/dev/null | sort | tail -1)
  if [ -n "${EFF:-}" ]; then
    say ""; say "   生效 profile vs 源文件（陷阱 T7，只应多出 execution 默认值）："
    diff "$CONF_LOCAL" "$EFF" | sed 's/^/     /' | head -60
  fi
  say ""; say "   关键行："
  sed 's/\x1b\[[0-9;]*m//g' "$LOGCAT" 2>/dev/null | grep -aoE \
    "invalid=[0-9]+|ksud ready|cpu pair: [^]]*|prepare_kernel_page [a-z]+ attempt=[0-9]+|prepare_kernel_page retry [0-9]+/[0-9]+|=== W[0-9][^=]*===|W[0-9]: [A-Za-z]+ attempt [0-9]+/[0-9]+|route_done status=[-0-9]+|success=[01]|CMP_REQUEUE_PI ret=[-0-9]+ errno=[0-9]+|Write [0-9] failed|child is root!|exploit complete|KernelSU ready|vr guard: [^\"]*|enforce=[01]" \
    | sort | uniq -c | sed 's/^/     /' | head -30
  say ""; say "   logcat: $LOGCAT ($(wc -c < "$LOGCAT" | tr -d ' ') 字节)"
  hr
  say "判读（别把预期行为当失败）："
  say "  · CMP_REQUEUE_PI errno=35 (EDEADLK) / disarm errno=110 (ETIMEDOUT) 都是流程预期"
  say "  · 判成功要四个一起：route_done status=0 + success=1 + 写验证通过 + KernelSU ready"
  say "  · child is root! 在 handoff 之前打印，不是终点"
  say "  · route success=1 却 W1 全败 → 不是不稳定，是地址错，见 SKILL.md 的排查顺序"
  exit 0
}
trap cleanup INT TERM

hr
say "去 app 里导入 $CONF_NAME 并点运行（单 route、别手动改 CPU 对）。"
say "跑完或设备复位回来后按 Ctrl-C 收尾。实时落盘：$LOGCAT"
hr
tail -f "$LOGCAT" 2>/dev/null | grep -aE --line-buffered \
  "ghostlock|GhostLock|invalid=|ksud|cpu pair|prepare_kernel_page|=== W|route_done|success=|CMP_REQUEUE_PI|Write [0-9]|child is root|exploit complete|KernelSU|vr guard|enforce=|logcat (attached|detached)" \
  || true
wait
