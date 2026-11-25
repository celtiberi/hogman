#!/usr/bin/env bash
# ops-snapshot: fixed, argument-free, no-network host telemetry collector for
# Hogman Fleet Ops v1.
#
# Writes a sanitized single-host JSON snapshot atomically to
# /run/hogman-ops/snapshot.json (mode 0640, owner root:65532).
#
# Privacy & isolation guarantees:
# - Never opens customer pen data directories ($HOGMAN_HOME/pens/<name>/data).
# - Never reads or emits waiting-list emails, preferred pen names, or notes —
#   only counts (waiting, invited) and age of the oldest waiting entry.
# - Reads container memory from Linux cgroup files rather than `docker stats`.
set -euo pipefail

if [ $# -ne 0 ]; then
  echo "ops-snapshot: takes no arguments" >&2
  exit 2
fi

HOGMAN_HOME="${HOGMAN_HOME:-/opt/hogman}"
SNAPSHOT_DIR="${OPS_SNAPSHOT_DIR:-/run/hogman-ops}"
BACKUPS_DIR="${OPS_BACKUPS_DIR:-/var/backups/hogman}"
PROC_DIR="${OPS_PROC_DIR:-/proc}"
CGROUP_ROOT="${OPS_CGROUP_ROOT:-/sys/fs/cgroup}"
PENS_DIR="$HOGMAN_HOME/pens"
HOSTENV="$HOGMAN_HOME/host.env"
SIGNUP_WAITLIST="$HOGMAN_HOME/signup/waitlist"

command -v jq >/dev/null 2>&1 || { echo "ops-snapshot: jq is required" >&2; exit 1; }

now_epoch="$(date -u +%s)"
generated_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

parse_iso_epoch() {
  local ts="${1:-}"
  [ -n "$ts" ] || return 1
  # Strip fractional seconds if present so both GNU and BSD date parse cleanly.
  local clean
  clean="$(printf '%s' "$ts" | sed -E 's/\.[0-9]+Z$/Z/')"
  date -u -d "$clean" +%s 2>/dev/null \
    || date -j -u -f "%Y-%m-%dT%H:%M:%SZ" "$clean" +%s 2>/dev/null \
    || return 1
}

read_host_var() {
  local key="$1" def="$2" val=""
  if [ -r "$HOSTENV" ]; then
    val="$(awk -F= -v k="$key" '$1 == k { v = substr($0, index($0, "=") + 1) } END { print v }' "$HOSTENV" \
      | sed -E "s/^'(.*)'$/\1/; s/^\"(.*)\"$/\1/")"
  fi
  printf '%s' "${val:-$def}"
}

read_pen_env() {
  local f="$1" key="$2"
  [ -r "$f" ] || return 0
  awk -F= -v k="$key" '$1 == k { v = substr($0, index($0, "=") + 1) } END { print v }' "$f" \
    | tr -d '\r'
}

cgroup_mem_bytes() {
  local cid="$1" p
  for p in \
    "$CGROUP_ROOT/system.slice/docker-${cid}.scope/memory.current" \
    "$CGROUP_ROOT/docker/${cid}/memory.current" \
    "$CGROUP_ROOT/memory/docker/${cid}/memory.usage_in_bytes"; do
    if [ -r "$p" ]; then
      local v
      v="$(tr -dc '0-9' < "$p" || true)"
      if [ -n "$v" ]; then
        printf '%s' "$v"
        return 0
      fi
    fi
  done
  printf '0'
}

# Collect recent SetPolicy durations (dur_ms=<int>) from a running registrar
# container's stdout/stderr logs (no access to pens/<name>/data). Anchors
# strictly to registrar's log format, bounds values to <= 3600000 ms (1h) so
# malformed/injected numbers can never overflow Go int64 JSON decoding, and
# computes "<samples> <last_ms> <p95_ms>" over the latest 100 pushes in one awk.
collect_setpolicy_stats() {
  local cname="$1" logs_out
  if command -v timeout >/dev/null 2>&1; then
    logs_out="$(timeout 5s docker logs --tail 500 "$cname" 2>&1 || true)"
  else
    logs_out="$(docker logs --tail 500 "$cname" 2>&1 || true)"
  fi
  if [ -z "$logs_out" ]; then
    printf '0 0 0\n'
    return 0
  fi
  LC_ALL=C awk '
    { sub(/\r$/, "") }
    /^([0-9][0-9][0-9][0-9]\/[0-9][0-9]\/[0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9] )?policy: (applied|failed) gen=[0-9]+ bytes=[0-9]+ dur=[^ ]+ dur_ms=[0-9]+( err=.*)?$/ {
      tok = ""
      for (i = 1; i <= NF; i++) {
        if (substr($i, 1, 7) == "dur_ms=") {
          tok = substr($i, 8)
          break
        }
      }
      if (tok ~ /^[0-9]+$/ && length(tok) <= 8) {
        n = tok + 0
        if (n >= 0 && n <= 3600000) {
          total++
          ring[(total - 1) % 100] = n
          last_ms = n
        }
      }
    }
    END {
      if (total == 0) {
        print "0 0 0"
        exit
      }
      count = (total < 100) ? total : 100
      for (i = 0; i < count; i++) {
        a[i + 1] = ring[i]
      }
      for (i = 2; i <= count; i++) {
        v = a[i]
        j = i - 1
        while (j >= 1 && a[j] > v) {
          a[j + 1] = a[j]
          j--
        }
        a[j + 1] = v
      }
      idx = int((count * 95 + 99) / 100)
      if (idx < 1) idx = 1
      if (idx > count) idx = count
      printf "%d %.0f %.0f\n", count, last_ms, a[idx]
    }
  ' <<<"$logs_out"
}

# --- Host identity & OS metrics ---
host_name="$(hostname -s 2>/dev/null || hostname 2>/dev/null || echo unknown)"
version="unknown"
if [ -r "$HOGMAN_HOME/VERSION" ]; then
  version="$(tr -d '\r\n' < "$HOGMAN_HOME/VERSION")"
  [ -n "$version" ] || version="unknown"
fi

uptime_sec=0
if [ -r "$PROC_DIR/uptime" ]; then
  uptime_sec="$(awk '{ printf "%.0f", $1 }' "$PROC_DIR/uptime" 2>/dev/null || echo 0)"
fi

load1=0 load5=0 load15=0
if [ -r "$PROC_DIR/loadavg" ]; then
  read -r load1 load5 load15 _ < "$PROC_DIR/loadavg" || true
fi

ram_total=0 ram_used=0 swap_total=0 swap_used=0
if [ -r "$PROC_DIR/meminfo" ]; then
  read -r ram_total ram_used swap_total swap_used < <(awk '
    $1 == "MemTotal:"     { mt = $2 * 1024 }
    $1 == "MemAvailable:" { ma = $2 * 1024 }
    $1 == "SwapTotal:"    { st = $2 * 1024 }
    $1 == "SwapFree:"     { sf = $2 * 1024 }
    END {
      ru = (mt > ma) ? (mt - ma) : 0
      su = (st > sf) ? (st - sf) : 0
      printf "%.0f %.0f %.0f %.0f\n", mt+0, ru+0, st+0, su+0
    }' "$PROC_DIR/meminfo")
fi

disk_total=0 disk_used=0
disk_target="$HOGMAN_HOME"
[ -d "$disk_target" ] || disk_target="/"
read -r disk_total disk_used < <(df -k -P "$disk_target" 2>/dev/null | awk 'NR == 2 { printf "%.0f %.0f\n", $2 * 1024, $3 * 1024 }' || echo "0 0")

# --- Container snapshot (ID, Name, State) in one local call ---
docker_rows=""
if [ "${OPS_SKIP_DOCKER:-0}" != "1" ] && command -v docker >/dev/null 2>&1; then
  docker_rows="$(docker ps -a --no-trunc --format '{{.ID}} {{.Names}} {{.State}}' 2>/dev/null || true)"
fi

# --- Services ---
unit_state() {
  local unit="$1"
  if [ "${OPS_SKIP_SYSTEMD:-0}" != "1" ] && command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl is-active "$unit" 2>/dev/null || true
  else
    printf 'unknown'
  fi
}

container_service_state() {
  local cname="$1" st
  if [ -z "$docker_rows" ]; then
    printf 'unknown'
    return 0
  fi
  st="$(awk -v name="$cname" '$2 == name { print $3; exit }' <<<"$docker_rows")"
  case "$st" in
    running) printf 'active' ;;
    "")      printf 'inactive' ;;
    *)       printf '%s' "$st" ;;
  esac
}

svc_cdns="$(unit_state hogman-challenge-dns.service)"
svc_gate="$(unit_state hogman-gate-cert.service)"
svc_life="$(unit_state hogman-lifecycle.timer)"
svc_broker="$(container_service_state hogman-signup-broker-1)"
svc_web="$(container_service_state hogman-signup-web-1)"

# --- Last backup timestamp ---
last_backup_at=""
if [ -d "$BACKUPS_DIR" ]; then
  newest_ts="$(find "$BACKUPS_DIR" -maxdepth 1 -type f -name '*.tar.gz.age' -exec basename {} \; 2>/dev/null \
    | sed -nE 's/.*-([0-9]{8}T[0-9]{6}Z)\.tar\.gz\.age$/\1/p' \
    | sort | tail -n 1 || true)"
  if [ -n "$newest_ts" ]; then
    last_backup_at="$(printf '%s' "$newest_ts" | sed -E 's/^([0-9]{4})([0-9]{2})([0-9]{2})T([0-9]{2})([0-9]{2})([0-9]{2})Z$/\1-\2-\3T\4:\5:\6Z/')"
  fi
fi

# --- Pens (host-level metadata only; never touches pens/<name>/data/) ---
max_pens="$(read_host_var MAX_PENS 8)"
renew_reserve="$(read_host_var RENEW_WAKE_RESERVE 2)"
[[ "$max_pens" =~ ^[0-9]+$ ]] || max_pens=8
[[ "$renew_reserve" =~ ^[0-9]+$ ]] || renew_reserve=2

live_count=0
sleeping_count=0
renew_only_count=0
pens_json="[]"

if [ -d "$PENS_DIR" ]; then
  while IFS= read -r pen_dir; do
    [ -d "$pen_dir" ] || continue
    n="$(basename "$pen_dir")"
    [[ "$n" =~ ^[a-z0-9][a-z0-9-]*$ ]] || continue
    [ -f "$pen_dir/.env" ] || [ -f "$pen_dir/.retired" ] || [ -f "$pen_dir/.removed" ] || continue

    pub_host="$(read_pen_env "$pen_dir/.env" PUBLIC_HOST)"
    plan="$(read_pen_env "$pen_dir/.env" PLAN)"
    [ -n "$plan" ] || plan="personal"
    theme="$(read_pen_env "$pen_dir/.env" THEME)"
    [ -n "$theme" ] || theme="default"

    state="running"
    if [ -f "$pen_dir/.retired" ]; then
      state="deleted"
    elif [ -f "$pen_dir/.renew-wake" ]; then
      state="renew_only"
    elif [ -f "$pen_dir/.sleeping" ]; then
      state="sleeping"
    elif [ -f "$pen_dir/.removed" ]; then
      state="stopped"
    fi

    paid_until=""
    delete_after=""
    if [ -r "$pen_dir/lifecycle.json" ]; then
      paid_until="$(jq -r '.paid_until // empty' "$pen_dir/lifecycle.json" 2>/dev/null || true)"
      delete_after="$(jq -r '.delete_after // empty' "$pen_dir/lifecycle.json" 2>/dev/null || true)"
    fi

    c_total=0
    c_up=0
    ram_bytes=0
    hs_running=0
    reg_running=0
    sp_samples=0
    sp_last_ms=0
    sp_p95_ms=0
    if [ -n "$docker_rows" ]; then
      while IFS=' ' read -r cid cname cstate; do
        [ -n "$cid" ] || continue
        case "$cname" in
          "pen-${n}-"*)
            c_total=$((c_total + 1))
            if [ "$cstate" = "running" ]; then
              c_up=$((c_up + 1))
              if [ "$cname" = "pen-${n}-headscale-1" ]; then
                hs_running=1
              elif [ "$cname" = "pen-${n}-registrar-1" ]; then
                reg_running=1
              fi
              mem="$(cgroup_mem_bytes "$cid")"
              ram_bytes=$((ram_bytes + mem))
            fi
            ;;
        esac
      done <<<"$docker_rows"
      if [ "$state" = "running" ] && [ "$hs_running" -eq 0 ]; then
        state="down"
      fi
      if [ "$reg_running" -eq 1 ]; then
        read -r sp_samples sp_last_ms sp_p95_ms < <(collect_setpolicy_stats "pen-${n}-registrar-1") || { sp_samples=0; sp_last_ms=0; sp_p95_ms=0; }
        [[ "$sp_samples" =~ ^[0-9]+$ ]] || sp_samples=0
        [[ "$sp_last_ms" =~ ^[0-9]+$ ]] || sp_last_ms=0
        [[ "$sp_p95_ms" =~ ^[0-9]+$ ]] || sp_p95_ms=0
      fi
    fi

    if [ ! -f "$pen_dir/.removed" ] && [ ! -f "$pen_dir/.sleeping" ] && [ ! -f "$pen_dir/.retired" ]; then
      live_count=$((live_count + 1))
    fi
    if [ -f "$pen_dir/.sleeping" ] && [ ! -f "$pen_dir/.removed" ] && [ ! -f "$pen_dir/.retired" ]; then
      sleeping_count=$((sleeping_count + 1))
    fi
    if [ -f "$pen_dir/.renew-wake" ] && [ ! -f "$pen_dir/.removed" ] && [ ! -f "$pen_dir/.retired" ]; then
      renew_only_count=$((renew_only_count + 1))
    fi

    pens_json="$(jq -c \
      --arg name "$n" \
      --arg pub_host "$pub_host" \
      --arg plan "$plan" \
      --arg theme "$theme" \
      --arg state "$state" \
      --arg paid_until "$paid_until" \
      --arg delete_after "$delete_after" \
      --argjson c_up "$c_up" \
      --argjson c_total "$c_total" \
      --argjson ram "$ram_bytes" \
      --argjson sp_samples "${sp_samples:-0}" \
      --argjson sp_last_ms "${sp_last_ms:-0}" \
      --argjson sp_p95_ms "${sp_p95_ms:-0}" \
      '. + [{
        name: $name,
        public_host: $pub_host,
        plan: $plan,
        theme: $theme,
        state: $state,
        paid_until: $paid_until,
        delete_after: $delete_after,
        containers_up: $c_up,
        containers_total: $c_total,
        ram_bytes: $ram,
        setpolicy_samples: $sp_samples,
        setpolicy_last_ms: $sp_last_ms,
        setpolicy_p95_ms: $sp_p95_ms
      }]' <<<"$pens_json")"
  done < <(find "$PENS_DIR" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort)
fi

# --- Waitlist counts + oldest waiting entry age only (zero emails/notes) ---
wl_waiting=0
wl_invited=0
wl_oldest_age=0
if [ -r "$SIGNUP_WAITLIST" ]; then
  read -r wl_waiting wl_invited wl_oldest_ts < <(awk -F'\t' '
    $3 == "waiting" {
      w++
      if ($2 != "" && (oldest == "" || $2 < oldest)) oldest = $2
    }
    $3 ~ /^invited / { inv++ }
    END { printf "%d %d %s\n", w+0, inv+0, oldest }
  ' "$SIGNUP_WAITLIST")
  if [ "$wl_waiting" -gt 0 ] && [ -n "${wl_oldest_ts:-}" ]; then
    if oldest_epoch="$(parse_iso_epoch "$wl_oldest_ts")"; then
      if [ "$now_epoch" -gt "$oldest_epoch" ]; then
        wl_oldest_age=$((now_epoch - oldest_epoch))
      fi
    fi
  fi
fi

mkdir -p "$SNAPSHOT_DIR"
if [ "$(id -u)" -eq 0 ]; then
  if [ "$(stat -c '%u:%g' "$SNAPSHOT_DIR" 2>/dev/null || true)" != "0:65532" ]; then
    chown 0:65532 "$SNAPSHOT_DIR"
  fi
  chmod 0750 "$SNAPSHOT_DIR"
fi
tmp_file="$SNAPSHOT_DIR/.snapshot.json.tmp.$$"
trap 'rm -f "$tmp_file"' EXIT

jq -n \
  --arg generated_at "$generated_at" \
  --arg host_name "$host_name" \
  --arg version "$version" \
  --argjson uptime_sec "${uptime_sec:-0}" \
  --argjson load1 "${load1:-0}" \
  --argjson load5 "${load5:-0}" \
  --argjson load15 "${load15:-0}" \
  --argjson ram_used "${ram_used:-0}" \
  --argjson ram_total "${ram_total:-0}" \
  --argjson swap_used "${swap_used:-0}" \
  --argjson swap_total "${swap_total:-0}" \
  --argjson disk_used "${disk_used:-0}" \
  --argjson disk_total "${disk_total:-0}" \
  --argjson cap_live "$live_count" \
  --argjson cap_max "$max_pens" \
  --argjson cap_sleeping "$sleeping_count" \
  --argjson cap_renew_only "$renew_only_count" \
  --argjson cap_renew_reserve "$renew_reserve" \
  --arg svc_cdns "${svc_cdns:-unknown}" \
  --arg svc_gate "${svc_gate:-unknown}" \
  --arg svc_life "${svc_life:-unknown}" \
  --arg svc_broker "${svc_broker:-unknown}" \
  --arg svc_web "${svc_web:-unknown}" \
  --arg last_backup_at "$last_backup_at" \
  --argjson pens "$pens_json" \
  --argjson wl_waiting "$wl_waiting" \
  --argjson wl_invited "$wl_invited" \
  --argjson wl_oldest_age "$wl_oldest_age" \
  '{
    generated_at: $generated_at,
    host: {
      name: $host_name,
      version: $version,
      uptime_sec: $uptime_sec,
      load: [$load1, $load5, $load15],
      ram_used_bytes: $ram_used,
      ram_total_bytes: $ram_total,
      swap_used_bytes: $swap_used,
      swap_total_bytes: $swap_total,
      disk_used_bytes: $disk_used,
      disk_total_bytes: $disk_total,
      capacity: {
        live: $cap_live,
        max: $cap_max,
        sleeping: $cap_sleeping,
        renew_only: $cap_renew_only,
        renew_reserve: $cap_renew_reserve
      },
      services: {
        "challenge-dns": $svc_cdns,
        "gate-cert": $svc_gate,
        "lifecycle.timer": $svc_life,
        "signup-broker": $svc_broker,
        "signup-web": $svc_web
      },
      last_backup_at: $last_backup_at
    },
    pens: $pens,
    waitlist: {
      waiting: $wl_waiting,
      invited: $wl_invited,
      oldest_waiting_age_sec: $wl_oldest_age
    }
  }' > "$tmp_file"

chmod 0640 "$tmp_file"
if [ "$(id -u)" -eq 0 ]; then
  if [ "$(stat -c '%u:%g' "$tmp_file" 2>/dev/null || true)" != "0:65532" ]; then
    chown 0:65532 "$tmp_file"
  fi
fi
mv -f "$tmp_file" "$SNAPSHOT_DIR/snapshot.json"
trap - EXIT
