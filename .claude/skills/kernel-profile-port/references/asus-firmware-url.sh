#!/usr/bin/env bash
# 查 ASUS 官方固件 ZIP 的直链（ROG / ZenFone 手机同样适用）。
#
#   ./asus-firmware-url.sh "ROG Phone 9"          # 国行（CN 站 + CN CDN）
#   ./asus-firmware-url.sh "ROG Phone 9" global   # 全球站
#
# 接口取自 RSSHub `lib/routes/asus/bios.tsx`（DIYgod/RSSHub，在维护中的实现）：
#   1) odinapi SearchSuggestion   机型名 -> DataId（产品 ID）
#   2) GetPDBIOS                  产品 ID -> 固件文件列表（手机固件归在 BIOS & FIRMWARE 分类）
#   3) dlcdnets                   拼出直链
#
# 两点注意：
# - 这是 ASUS 下载中心的内部 API，无公开文档，字段可能随时变。对不上先 dump 原始 JSON，不要猜。
# - 国行走 .com.cn 的 odinapi / www / dlcdnets 三件套，和全球站是不同的产品 ID 空间。
set -euo pipefail

MODEL=${1:?用法: $0 "<机型名>" [cn|global]}
SITE=${2:-cn}

case "${SITE}" in
  cn)
    ODIN=https://odinapi.asus.com.cn; WEB=https://www.asus.com.cn
    WC=cn; SITELANG=cn; CDN=https://dlcdnets.asus.com.cn; URLKEY=China ;;
  global)
    ODIN=https://odinapi.asus.com; WEB=https://www.asus.com
    WC=global; SITELANG=en; CDN=https://dlcdnets.asus.com; URLKEY=Global ;;
  *)
    echo "第二个参数只能是 cn 或 global" >&2; exit 2 ;;
esac

KEY=$(printf %s "${MODEL}" | sed "s/ /%20/g")
SEARCH="${ODIN}/recent-data/apiv2/SearchSuggestion?SystemCode=asus&WebsiteCode=${WC}&SearchKey=${KEY}&SearchType=ProductsAll&RowLimit=4&sitelang=${SITELANG}"

RAW=$(curl -sSfL "${SEARCH}") || { echo "搜索接口请求失败：检查网络/出口策略是否放通 ${ODIN}" >&2; exit 1; }

PDID=$(printf %s "${RAW}" | python3 -I -c "
import json, sys
d = json.load(sys.stdin)
try:
    p = d[chr(82)+'esult'][0]['Content'][0]
except (KeyError, IndexError, TypeError):
    sys.exit('没搜到该机型，换个写法再试（如 AI2501 / ROG Phone 9 Pro）')
print(p['DataId'])
print('matched:', p.get('Title', ''), p.get('Url', ''), file=sys.stderr)
")

echo "pdid=${PDID}" >&2

BIOS=$(curl -sSfL "${WEB}/support/webapi/ProductV2/GetPDBIOS?website=${WC}&pdid=${PDID}") \
  || { echo "固件列表接口请求失败：检查 ${WEB} 是否可达" >&2; exit 1; }

printf %s "${BIOS}" | CDN="${CDN}" URLKEY="${URLKEY}" python3 -I -c "
import json, os, sys
cdn = os.environ['CDN']
key = os.environ['URLKEY']
d = json.load(sys.stdin)
objs = (d.get('Result') or {}).get('Obj') or []
if not objs:
    sys.exit('没有 BIOS/FIRMWARE 条目；手机固件也可能挂在别的分类（试 GetPDDrivers），先 dump 原始 JSON')
for f in objs[0].get('Files', []):
    u = (f.get('DownloadUrl') or {}).get(key) or ''
    print('%-30s %10s  %s' % (f.get('Version', '?'), f.get('FileSize', '?'),
                              cdn + u if u else '(this region has no direct url)'))
"
