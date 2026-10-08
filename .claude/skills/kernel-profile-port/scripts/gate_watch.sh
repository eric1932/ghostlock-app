#!/usr/bin/env bash
# gate_watch.sh — 阶段 4 真机门禁的主机侧记录器（app 流程）。
#
#   GL_CONF=~/path/<uname-r>.conf bash gate_watch.sh [标签]
#   GL_SERIAL=<序列号>              多台设备同时连着时必须给
#
# 这个脚本不驱动 exploit，只负责记录：你在 app 里导入 conf、点运行，它在主机上
# 同时抓两路，跑完按 Ctrl-C 收尾。
#
# ── 抓两路，而且 exploit trace 在第二路（陷阱 T8）──────────────
# 第 1 路 logcat：**不含 exploit 的任何输出**。app 的 `<k>` 行和 native 的
#   `[spray]` / `prepare_kernel_page` / `=== W1` 全都只进 app 自己的调试日志文件，
#   logcat 里关于它只有 auditd 的 avc 回显。logcat 仍要抓，因为内核 panic、
#   avc denied、掉线/重连时刻只在这一路。
# 第 2 路 device trace：app 把 trace 写到
#   `/sdcard/Download/ghostlock-debug-log/<时间戳>/ghostlock-direct-*.log.txt`，
#   每行 flush 但**不 fsync**（`DebugAttackLog.append`），而且文件是通过
#   MediaStore 建的。于是内核 panic / 看门狗复位后 f2fs 回滚到上一个 checkpoint，
#   **整个目录连带那次运行的 trace 一起消失** —— 实测过，panic 那次一个字节都没留下，
#   而且那台机器 pstore 是空的，连内核侧现场都没有。
#   所以必须在设备还活着的时候就把它轮询快照到主机。
#
#   快照规则（别简化）：按**路径**分组，同一路径内只在变长时替换（设备侧截断/回滚
#   伤不到主机这份），路径一变就清空重来。**不要**用"忽略启动时的最新目录"当基线 ——
#   踩过：app 的 run 目录比脚本早建 3 秒，整次 trace 被当成"上一次的"全扔了。
#   现在是无条件跟最新路径，收尾时会打印 trace 到底来自哪个目录，自己核一眼时间戳。
#
# ── 落盘纪律，别改回去 ─────────────────────────────────────────
# adb 的 stdin 必须接 /dev/null。adb 若落在后台进程组里又去动控制终端
# (tcsetattr) 会吃 SIGTTOU 被挂起 —— 命令已经发给设备、exploit 照跑、设备照卡，
# 但 adb 不读不写，**日志 0 字节**。所以：不用 set -m、不套子 shell，并且下面
# 有预检，先用无害命令确认流式输出真的在涨，再让你去点运行。
#
# CLI 流程（`--load-prebuilt-profile`）请另写驱动脚本：那边脚本是父进程，能在
# `prepare_kernel_page retry` 处就地 abort 重摇；app 流程里控制权不在脚本手里。
# 两个流程的 uid / seccomp / W3 都不同，成功率不能互比。
# ──────────────────────────────────────────────────────────────
set -u

PKG=${GL_PKG:-com.ghostlock.app}
CONF_LOCAL=${GL_CONF:?用法: GL_CONF=<本地 .conf 路径> bash $0 [标签]}
CONF_NAME=$(basename "${CONF_LOCAL}")
CONF_DEV=${GL_CONF_DEV:-/sdcard/Download/${CONF_NAME}}
TRACE_GLOB=${GL_TRACE_GLOB:-/sdcard/Download/ghostlock-debug-log/*/*.log.txt}
POLL=${GL_POLL_SEC:-0.5}

say() { printf '%s\n' "$*"; }
hr()  { printf '%s\n' "────────────────────────────────────────────────────────"; }

command -v adb >/dev/null || { say "需要 adb"; exit 1; }
[ -r "${CONF_LOCAL}" ] || { say "读不到 ${CONF_LOCAL}"; exit 1; }

# ── 设备钉选：多台连着时 adb 会歧义（踩过：ROG 和 vivo 同时在，还一台两路）──
NDEV=$(adb devices | sed '1d' | grep -cE '[[:space:]](device|recovery)$')
if [ -z "${GL_SERIAL:-}" ] && [ "${NDEV}" -gt 1 ]; then
  say "连着 ${NDEV} 台设备，adb 会歧义。用 GL_SERIAL=<序列号> 指定一台："
  adb devices -l | sed '1d' | sed 's/^/   /'
  exit 1
fi
ADB="adb"
[ -n "${GL_SERIAL:-}" ] && ADB="adb -s ${GL_SERIAL}"

TS=$(date +%Y%m%d-%H%M%S)
LABEL=$(printf '%s' "${1:-}" | tr -cs 'A-Za-z0-9._-' '-' | sed 's/^-*//; s/-*$//')
OUT=${GL_OUT_ROOT:-${HOME}/Downloads/gate-logs}/${TS}${LABEL:+-${LABEL}}
mkdir -p "${OUT}"
LOGCAT="${OUT}/logcat.log"
TRACE="${OUT}/device-trace.log"
: > "${TRACE}"

hr; say "1. 前置检查（全部只读）"
${ADB} wait-for-device
UNAME=$(${ADB} shell uname -r 2>/dev/null | tr -d '\r')
# profile 的 release 字段就是必须匹配的 uname -r
EXPECT_UNAME=$(sed -nE 's/^[[:space:]]*release[[:space:]]*=[[:space:]]*"?([^"]+)"?.*/\1/p' "${CONF_LOCAL}" | head -1)
EXPECT_SHA=$(shasum -a 256 "${CONF_LOCAL}" | awk '{print $1}')
say "   设备          : $(${ADB} shell getprop ro.product.model 2>/dev/null | tr -d '\r')${GL_SERIAL:+ (${GL_SERIAL})}"
say "   uname -r      : ${UNAME}"
say "   profile release: ${EXPECT_UNAME}"
if [ -z "${EXPECT_UNAME}" ] || [ "${UNAME}" != "${EXPECT_UNAME}" ]; then
  say "   ✗ 不一致（不变量 1）。停。"; exit 1
fi
say "   ✓ 逐字符一致"

GOT_SHA=$(${ADB} shell "sha256sum '${CONF_DEV}' 2>/dev/null" | awk '{print $1}' | tr -d '\r')
if [ "${GOT_SHA}" != "${EXPECT_SHA}" ]; then
  say "   ✗ 设备上的 conf 哈希不对或文件不在：${GOT_SHA:-<缺失>}"
  say "     ${ADB} push '${CONF_LOCAL}' /sdcard/Download/"
  say "     推完要在 app 里**重新导入一次**，app 存的是自己那份副本。"
  exit 1
fi
say "   ✓ 设备 conf 哈希 = 本地 (${EXPECT_SHA:0:12}…)"

${ADB} shell "pm list packages" 2>/dev/null | grep -q "^package:${PKG}\$" \
  || { say "   ✗ ${PKG} 没装"; exit 1; }
say "   ✓ ${PKG} $(${ADB} shell "dumpsys package ${PKG} | grep -m1 versionName" 2>/dev/null | tr -d ' \r')"

# ksud 来自管理器 app 的 nativeLibraryDir；缺了 W1/W2 仍能拿 uid 0 但不会加载模块
MGR=$(${ADB} shell "pm list packages" 2>/dev/null | grep -oE 'me\.weishu\.kernelsu(\.pr)?|com\.resukisu\.resukisu|com\.kowx712\.supermanager' | head -1)
[ -n "${MGR}" ] && say "   ✓ 管理器 ${MGR}（提供 ksud）" \
                || say "   ⚠ 没有 KernelSU/ReSukiSU/KowSU —— 不会加载模块，门禁到不了 KernelSU ready"

# 冷机不是形式要求：实测同一份 conf、同一 CPU 对，冷机 0 次 prepare 重试 / 23 s，
# 开机半小时后 18 次重试 / 60 s，KernelSnitch 泄漏失败 0 次 vs 15 次。
${ADB} shell "cat /proc/modules 2>/dev/null" | grep -qi kernelsu \
  && say "   ⚠ KernelSU 已加载 —— 不是干净启动，先重启" \
  || say "   ✓ KernelSU 未加载"
UP=$(${ADB} shell "cat /proc/uptime" 2>/dev/null | awk '{printf "%d",$1}')
if [ "${UP:-0}" -gt 300 ]; then
  say "   启动时长      : ${UP}s   ⚠ 不是冷机 —— 重试次数和耗时会明显变差，建议先重启"
else
  say "   启动时长      : ${UP}s   ✓ 冷机"
fi
BOOTREASON=$(${ADB} shell getprop ro.boot.bootreason 2>/dev/null | tr -d '\r')
say "   上次启动原因  : ${BOOTREASON}$([ "${BOOTREASON}" = "kernel_panic" ] && echo '   ← 上一次是 panic')"

{ say "uname=${UNAME}"; say "conf=${CONF_NAME}"; say "conf_sha256=${GOT_SHA}"
  say "serial=${GL_SERIAL:-<single device>}"
  say "manager=${MGR:-none}"; say "uptime_at_start=${UP}s"
  say "bootreason_at_start=${BOOTREASON}"
  ${ADB} shell getprop ro.build.fingerprint 2>/dev/null | tr -d '\r' | sed 's/^/fingerprint=/'
  say "host_start=$(date -Iseconds)"; } > "${OUT}/identity.txt"

hr; say "2. 挂两路记录（设备复位自动重连）"
${ADB} logcat -c 2>/dev/null || true
stream() {
  while :; do
    ${ADB} wait-for-device
    printf '\n===== logcat attached %s =====\n' "$(date -Iseconds)" >> "${LOGCAT}"
    ${ADB} logcat -b all -v threadtime '*:V' >> "${LOGCAT}" 2>&1 < /dev/null
    printf '\n===== logcat detached %s (设备掉线/复位?) =====\n' "$(date -Iseconds)" >> "${LOGCAT}"
    sleep 1
  done
}
stream &
STREAM_PID=$!

TMPSNAP="${OUT}/.snap.tmp"
snapshot() {
  LAST_PATH=""
  while :; do
    if ${ADB} exec-out "f=\$(ls -1dt ${TRACE_GLOB} 2>/dev/null | head -1); printf '# --- device trace: %s ---\\n' \"\$f\"; [ -n \"\$f\" ] && cat \"\$f\"" \
         > "${TMPSNAP}" 2>/dev/null < /dev/null; then
      P=$(sed -n '1s/^# --- device trace: \(.*\) ---$/\1/p' "${TMPSNAP}" | tr -d '\r')
      if [ -n "${P}" ]; then
        if [ "${P}" != "${LAST_PATH}" ]; then
          LAST_PATH="${P}"; cp "${TMPSNAP}" "${TRACE}"      # 换了一次运行：无条件接管
        else
          NEW=$(wc -c < "${TMPSNAP}" | tr -d ' ')
          OLD=$(wc -c < "${TRACE}" | tr -d ' ')
          [ "${NEW:-0}" -gt "${OLD:-0}" ] && cp "${TMPSNAP}" "${TRACE}"
        fi
      fi
    fi
    sleep "${POLL}"
  done
}
snapshot &
SNAP_PID=$!

sleep 2; ${ADB} shell log -t GLGATE "stream preflight ${TS}" >/dev/null 2>&1; sleep 2
if grep -q "stream preflight ${TS}" "${LOGCAT}" 2>/dev/null; then
  say "   ✓ logcat 预检通过（这一路**没有** exploit 输出，只有 panic / avc / 掉线时刻）"
else
  say "   ✗ logcat 预检失败：标记没出现（$(wc -c < "${LOGCAT}" | tr -d ' ') 字节）。别继续，先修流。"
  kill "${STREAM_PID}" "${SNAP_PID}" 2>/dev/null; exit 1
fi
say "   ✓ trace 快照器已起（${POLL}s 轮询）→ $(basename "${TRACE}")"
say "     现在跟的是：$(sed -n 1p "${TRACE}" 2>/dev/null | sed 's/^# --- device trace: //; s/ ---$//')"
say "     点运行后新目录一出现会自动切过去，下面增量打印。"

cleanup() {
  trap - INT TERM
  hr; say "3. 收尾"
  kill "${SNAP_PID}" 2>/dev/null; wait "${SNAP_PID}" 2>/dev/null
  kill "${STREAM_PID}" 2>/dev/null; wait "${STREAM_PID}" 2>/dev/null
  rm -f "${TMPSNAP}"
  ${ADB} wait-for-device

  # 设备活着就再抓一次全量（含 profile.conf / profile.bin / kernel-info 这些 sidecar）
  ${ADB} pull /sdcard/Download/ghostlock-debug-log "${OUT}/device-debug-log" >/dev/null 2>&1 \
    && say "   ✓ ${OUT}/device-debug-log" || say "   （设备上没有 ghostlock-debug-log）"

  POST=$(${ADB} shell getprop ro.boot.bootreason 2>/dev/null | tr -d '\r')
  say "   本次启动原因  : ${POST}"
  if [ "${POST}" = "kernel_panic" ]; then
    say "   ⚠ 设备 panic 过。设备侧 trace 很可能被 f2fs 回滚掉了 ——"
    say "     以主机侧 $(basename "${TRACE}") 为准（下面的关键行就是从它里取的）。"
  fi

  EFF=$(find "${OUT}/device-debug-log" -name 'profile.conf' 2>/dev/null | sort | tail -1)
  if [ -n "${EFF:-}" ]; then
    say ""; say "   生效 profile vs 源文件（陷阱 T7，只应多出 execution 默认值）："
    diff "${CONF_LOCAL}" "${EFF}" | sed 's/^/     /' | head -60
  fi

  say ""
  say "   trace 来自：$(sed -n 1p "${TRACE}" 2>/dev/null | sed 's/^# --- device trace: //; s/ ---$//')"
  say "   ↑ 核一眼时间戳是不是本次运行。$(wc -c < "${TRACE}" | tr -d ' ') 字节"
  say ""; say "   关键行："
  sed 's/\x1b\[[0-9;]*m//g' "${TRACE}" 2>/dev/null | grep -aoE \
    "invalid=[0-9]+|ksud ready|cpu pair: [^]]*|prepare_kernel_page [a-z]+ attempt=[0-9]+|prepare_kernel_page retry [0-9]+/[0-9]+|=== W[0-9][^=]*===|W[0-9]: [A-Za-z]+ attempt [0-9]+/[0-9]+|route_done status=[-0-9]+|success=[01]|CMP_REQUEUE_PI ret=[-0-9]+ errno=[0-9]+|Write [0-9] (complete|failed)|vr\.ko [a-z ;]*|child_task=0x[0-9a-f]+|KernelSnitch [a-z_ ]*failed|child is root!|exploit complete|KernelSU ready" \
    | uniq -c | sed 's/^/     /' | head -40
  say ""
  say "   trace 最后 12 行（panic 时它就是断点）："
  sed 's/\x1b\[[0-9;]*m//g' "${TRACE}" 2>/dev/null | tail -12 | sed 's/^/     /'

  say ""
  say "   内核侧线索（panic / oops / 看门狗，取自 logcat）："
  sed 's/\x1b\[[0-9;]*m//g' "${LOGCAT}" 2>/dev/null | grep -aiE \
    "Unable to handle kernel|Internal error: Oops|BUG: |Kernel panic|watchdog|WARNING: CPU|Call trace" \
    | tail -12 | cut -c1-200 | sed 's/^/     /'

  say ""; say "   logcat: ${LOGCAT} ($(wc -c < "${LOGCAT}" | tr -d ' ') 字节)"
  say "   trace : ${TRACE}"
  hr
  say "判读（别把预期行为当失败）："
  say "  · CMP_REQUEUE_PI errno=35 (EDEADLK) / disarm errno=110 (ETIMEDOUT) 都是流程预期"
  say "  · 判成功要四个一起：route_done status=0 + success=1 + 写验证通过 + KernelSU ready"
  say "  · child is root! 在 handoff 之前打印，不是终点"
  say "  · W1 的验证就是能不能 open /sys/fs/selinux/enforce：enforcing 时 untrusted_app"
  say "    读不到，所以「读到了」本身即证明写落地了"
  say "  · route success=1 却 W1 全败 → **先重跑，再换 CPU 对**，最后才查地址。"
  say "    尤其看这个签名：prepare_kernel_page 每次都 ok attempt=1 却从不落地 = 假成功，"
  say "    换另一簇的 CPU 对（实测 4/5 不行、6/7 一次就过）。见 SKILL.md 阶段 4"
  exit 0
}
trap cleanup INT TERM

hr
say "去 app 里导入 ${CONF_NAME}、确认 CPU 对、点运行（单 route）。"
say "跑完或设备复位回来后按 Ctrl-C 收尾。"
say "  trace（看这个）: ${TRACE}"
say "  logcat         : ${LOGCAT}"
hr
# 实时视图：快照是整文件替换，所以不能用 tail -f（它会在截断处重放）。
# 只按行号增量打印；换运行时文件变短，重置行号从头打。
SHOWN=0
while :; do
  TOTAL=$(wc -l < "${TRACE}" 2>/dev/null | tr -d ' ')
  [ "${TOTAL:-0}" -lt "${SHOWN:-0}" ] && SHOWN=0
  if [ "${TOTAL:-0}" -gt "${SHOWN:-0}" ]; then
    sed -n "$((SHOWN + 1)),${TOTAL}p" "${TRACE}" 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g'
    SHOWN=${TOTAL}
  fi
  sleep "${POLL}"
done
