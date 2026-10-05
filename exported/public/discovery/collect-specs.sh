#!/usr/bin/env bash
#
# Agent Discovery collector for Linux / macOS - gathers OS/CPU/RAM/disk/system
# specs and installed package inventory, then reports them to the Agent
# Discovery backend (POST {Server}/discovery/agent/report).
#
# Usage:
#   DISCOVERY_SERVER_URL=https://assets.example.com/api \
#   DISCOVERY_AGENT_TOKEN=<token> \
#   ./collect-specs.sh
#
# Or pass the server URL as the first argument:
#   ./collect-specs.sh https://assets.example.com/api
#
set -euo pipefail

SERVER="${DISCOVERY_SERVER_URL:-${1:-}}"
TOKEN="${DISCOVERY_AGENT_TOKEN:-}"
ORG_SCHEMA="${DISCOVERY_ORG_SCHEMA:-}"
SERVER="${SERVER%/}"

if [ -z "$SERVER" ]; then
  echo "Usage: DISCOVERY_SERVER_URL=<url> [DISCOVERY_AGENT_TOKEN=<token>] $0" >&2
  exit 1
fi

# JSON-escape a string (backslash, double quote; strip control chars) so a
# package maintainer/model string with quotes can never break the payload.
jesc() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | tr -d '\000-\037'; }

HOSTNAME_VAL="$(hostname)"
CURRENT_USER="$(whoami)"

if [ "$(uname)" = "Darwin" ]; then
  OS_CAPTION="$(sw_vers -productName) $(sw_vers -productVersion)"
  OS_VERSION="$(sw_vers -productVersion)"
  OS_BUILD="$(sw_vers -buildVersion)"
  OS_ARCH="$(uname -m)"
  CPU_MODEL="$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo unknown)"
  CPU_CORES="$(sysctl -n hw.physicalcpu 2>/dev/null || echo 0)"
  CPU_LOGICAL="$(sysctl -n hw.logicalcpu 2>/dev/null || echo 0)"
  RAM_BYTES="$(sysctl -n hw.memsize 2>/dev/null || echo 0)"
  MANUFACTURER="Apple"
  MODEL="$(sysctl -n hw.model 2>/dev/null || echo unknown)"
  SERIAL="$(ioreg -l 2>/dev/null | awk -F'\"' '/IOPlatformSerialNumber/{print $4}')"
  SYS_UUID="$(ioreg -rd1 -c IOPlatformExpertDevice 2>/dev/null | awk -F'\"' '/IOPlatformUUID/{print $4}')"
  BIOS_VENDOR="Apple"
  BIOS_VERSION="$(system_profiler SPHardwareDataType 2>/dev/null | awk -F': ' '/Boot ROM|System Firmware/{print $2; exit}')"
  BIOS_DATE=""
else
  OS_CAPTION="$( (. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME") || uname -s)"
  OS_VERSION="$( (. /etc/os-release 2>/dev/null && echo "$VERSION_ID") || uname -r)"
  OS_BUILD="$(uname -r)"
  OS_ARCH="$(uname -m)"
  CPU_MODEL="$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | sed 's/^ *//' || echo unknown)"
  CPU_CORES="$(grep -c '^processor' /proc/cpuinfo 2>/dev/null || echo 0)"
  CPU_LOGICAL="$CPU_CORES"
  RAM_KB="$(grep MemTotal /proc/meminfo 2>/dev/null | awk '{print $2}')"
  RAM_BYTES=$(( ${RAM_KB:-0} * 1024 ))
  MANUFACTURER="$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null || echo unknown)"
  MODEL="$(cat /sys/class/dmi/id/product_name 2>/dev/null || echo unknown)"
  SERIAL="$(cat /sys/class/dmi/id/product_serial 2>/dev/null || echo unknown)"
  SYS_UUID="$(cat /sys/class/dmi/id/product_uuid 2>/dev/null || echo "")"
  BIOS_VENDOR="$(cat /sys/class/dmi/id/bios_vendor 2>/dev/null || echo "")"
  BIOS_VERSION="$(cat /sys/class/dmi/id/bios_version 2>/dev/null || echo "")"
  BIOS_DATE="$(cat /sys/class/dmi/id/bios_date 2>/dev/null || echo "")"
fi

RAM_GB="$(awk "BEGIN { printf \"%.1f\", ${RAM_BYTES:-0} / 1073741824 }")"

DISKS_JSON="[]"
if command -v df >/dev/null 2>&1; then
  DISKS_JSON="$(df -kP 2>/dev/null | tail -n +2 | awk '{printf "{\"model\":\"%s\",\"sizeGB\":%.1f,\"freeGB\":%.1f},", $6, $2/1048576, $4/1048576}' | sed 's/,$//')"
  DISKS_JSON="[$DISKS_JSON]"
fi

IP_ADDR="$( (ip route get 1 2>/dev/null | awk '{print $7; exit}') || (ifconfig 2>/dev/null | awk '/inet /{print $2; exit}') || echo "" )"
MAC_ADDR="$( (ip link show 2>/dev/null | awk '/ether/{print $2; exit}') || (ifconfig 2>/dev/null | awk '/ether/{print $2; exit}') || echo "" )"
GATEWAY="$( (ip route 2>/dev/null | awk '/^default/{print $3; exit}') || (netstat -rn 2>/dev/null | awk '/^default/{print $2; exit}') || echo "" )"
DNS_JSON="[]"
if [ -r /etc/resolv.conf ]; then
  DNS_JSON="$(awk '/^nameserver/{printf "\"%s\",", $2}' /etc/resolv.conf 2>/dev/null | sed 's/,$//')"
  DNS_JSON="[$DNS_JSON]"
fi

# ---- Installed software -----------------------------------------------------
# Parity with the Windows collectors: machine package manager (dpkg/rpm) PLUS
# the per-user / store-style sources (snap, flatpak system+user, Homebrew,
# macOS .app bundles in /Applications and ~/Applications). Every field goes
# through jesc() so odd characters cannot corrupt the JSON.
SW_ENTRIES=""
add_sw() { # name version publisher architecture productCode
  local n v p a c
  n="$(jesc "$1")"; v="$(jesc "$2")"; p="$(jesc "$3")"; a="$(jesc "$4")"; c="$(jesc "$5")"
  [ -z "$n" ] && return 0
  SW_ENTRIES="${SW_ENTRIES}{\"name\":\"$n\",\"version\":\"$v\",\"publisher\":\"$p\",\"architecture\":\"$a\",\"productCode\":\"$c\"},"
}

if command -v dpkg-query >/dev/null 2>&1; then
  while IFS=$'\t' read -r n v p a; do add_sw "$n" "$v" "$p" "$a" "$n"; done \
    < <(dpkg-query -W -f='${Package}\t${Version}\t${Maintainer}\t${Architecture}\n' 2>/dev/null || true)
elif command -v rpm >/dev/null 2>&1; then
  while IFS=$'\t' read -r n v p a; do add_sw "$n" "$v" "$p" "$a" "$n"; done \
    < <(rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\t%{ARCH}\n' 2>/dev/null || true)
fi

# Snap + Flatpak (system and per-user) - the Linux analogue of per-user/Store installs
if command -v snap >/dev/null 2>&1; then
  while read -r n v _ _ pub _; do [ "$n" = "Name" ] && continue; add_sw "$n" "$v" "$pub" "snap" "snap:$n"; done \
    < <(snap list 2>/dev/null || true)
fi
if command -v flatpak >/dev/null 2>&1; then
  while IFS=$'\t' read -r n id v; do add_sw "$n" "$v" "flatpak" "flatpak" "$id"; done \
    < <(flatpak list --app --columns=name,application,version 2>/dev/null || true)
  while IFS=$'\t' read -r n id v; do add_sw "$n" "$v" "flatpak (user)" "flatpak" "$id"; done \
    < <(flatpak list --user --app --columns=name,application,version 2>/dev/null || true)
fi

# macOS: Homebrew formulae + application bundles (system and per-user)
if [ "$(uname)" = "Darwin" ]; then
  if command -v brew >/dev/null 2>&1; then
    while read -r n v _; do add_sw "$n" "$v" "Homebrew" "brew" "$n"; done < <(brew list --versions 2>/dev/null || true)
  fi
  for appdir in /Applications "$HOME/Applications"; do
    [ -d "$appdir" ] || continue
    for app in "$appdir"/*.app; do
      [ -d "$app" ] || continue
      n="$(basename "$app" .app)"
      v="$(defaults read "$app/Contents/Info" CFBundleShortVersionString 2>/dev/null || echo "")"
      add_sw "$n" "$v" "" "app" "$n"
    done
  done
fi
SOFTWARE_JSON="[${SW_ENTRIES%,}]"

REPORTED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
PLATFORM="linux"
[ "$(uname)" = "Darwin" ] && PLATFORM="macos"

PAYLOAD=$(cat <<EOF
{
  "reportedAt": "$REPORTED_AT",
  "contractVersion": 2,
  "hostname": "$(jesc "$HOSTNAME_VAL")",
  "currentUser": "$(jesc "$CURRENT_USER")",
  "os": {"caption": "$(jesc "$OS_CAPTION")", "version": "$(jesc "$OS_VERSION")", "build": "$(jesc "$OS_BUILD")", "arch": "$(jesc "$OS_ARCH")"},
  "cpu": {"model": "$(jesc "$CPU_MODEL")", "cores": ${CPU_CORES:-0}, "logical": ${CPU_LOGICAL:-0}},
  "ramGB": $RAM_GB,
  "disks": $DISKS_JSON,
  "bios": {"vendor": "$(jesc "$BIOS_VENDOR")", "version": "$(jesc "$BIOS_VERSION")", "releaseDate": "$(jesc "$BIOS_DATE")"},
  "system": {"manufacturer": "$(jesc "$MANUFACTURER")", "model": "$(jesc "$MODEL")", "serial": "$(jesc "$SERIAL")", "uuid": "$(jesc "$SYS_UUID")"},
  "network": {"ip": "$IP_ADDR", "mac": "$MAC_ADDR", "gateway": "$GATEWAY", "dns": $DNS_JSON},
  "software": $SOFTWARE_JSON,
  "agent": {"platform": "$PLATFORM", "script": "collect-specs.sh"}
}
EOF
)

HEADERS=(-H "Content-Type: application/json")
[ -n "$TOKEN" ] && HEADERS+=(-H "x-agent-token: $TOKEN")
[ -n "$ORG_SCHEMA" ] && HEADERS+=(-H "x-org-schema: $ORG_SCHEMA")

curl -sS -X POST "${HEADERS[@]}" -d "$PAYLOAD" "$SERVER/discovery/agent/report" \
  && echo "Reported specs for $HOSTNAME_VAL to $SERVER" \
  || { echo "Failed to report to $SERVER" >&2; exit 1; }
