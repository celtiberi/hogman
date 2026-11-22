#!/bin/bash
# Watch a Hogman server from a machine you own, and push an alert to your
# phone when something breaks. Run it every few minutes.
#
#   NTFY_TOPIC=<secret topic> hogman-watch.sh <control-host> [backup-folder]
#
# Alerts go through ntfy (https://ntfy.sh): install its app, subscribe to the
# topic. No account. Anyone who knows the topic name can read it, so make it
# long and random:  echo hogman-$(openssl rand -hex 12)
#
# Checks: Headscale answers; the control host answers as a pen; its
# certificate (on a gate host, the *.gate wildcard) has more than a quarter of
# its life left, capped at 30 days; on a pen with public certificates, that the
# challenge DNS for the pens zone answers (needs dig); and, given a backup
# folder (where backup-pull.sh puts them), that a backup arrived in the last
# 36 hours.
# Alerts after two failures in a row, reminds every 6 hours, says when it's
# back. Says nothing if this machine itself is offline. WATCH_URLS (space-
# separated) adds other pages that must answer, such as a sign-up page.
#
#   hogman-watch.sh --test     send a test alert
set -uo pipefail
: "${NTFY_TOPIC:?set NTFY_TOPIC}"
NTFY="${NTFY_SERVER:-https://ntfy.sh}/$NTFY_TOPIC"
STATE="${STATE_DIR:-$HOME/.hogman-watch}"
mkdir -p "$STATE"

push() {  # push <title> <message> <priority> <tags>
  curl -fsS -m 20 -H "Title: $1" -H "Priority: $3" -H "Tags: $4" -d "$2" "$NTFY" >/dev/null
}
log() { echo "$(date -u +%FT%TZ) $*"; }

if [ "${1:-}" = --test ]; then
  push "Hogman watch" "Test alert from $(hostname -s). If you can read this, alerts work." default pig
  exit
fi
HOST="${1:?usage: hogman-watch.sh <control-host> [backup-folder]}"
BACKUPS="${2:-}"

# Our own connection first: no internet here is not the server's fault.
curl -fsS -m 10 -o /dev/null https://1.1.1.1/cdn-cgi/trace || { log "this machine is offline; skipping"; exit 0; }

c_headscale() { local out; out="$(curl -fsS -m 15 "https://$HOST/health")" || return 1; grep -q '"pass"' <<<"$out"; }
c_pen()       { local out; out="$(curl -fsS -m 15 "https://$HOST/hogman/v1/network")" || return 1; grep -Eq '"zone":"[a-z0-9-]+(\.[a-z0-9-]+)+"' <<<"$out"; }
epoch() { date -u -j -f "%b %e %T %Y %Z" "$1" +%s 2>/dev/null || date -u -d "$1" +%s 2>/dev/null; }
c_cert() {  # alert with a quarter of the lifetime left (at most 30 days): renewal starts at a third
  local pem nb na left
  pem="$(echo | openssl s_client -connect "$HOST:443" -servername "$HOST" 2>/dev/null | openssl x509 2>/dev/null)"
  [ -n "$pem" ] || return 1
  nb="$(epoch "$(openssl x509 -noout -startdate <<<"$pem" | cut -d= -f2)")"
  na="$(epoch "$(openssl x509 -noout -enddate <<<"$pem" | cut -d= -f2)")"
  [ -n "$nb" ] && [ -n "$na" ] || return 1
  left=$(( (na - nb) / 4 )); [ "$left" -gt $((30 * 86400)) ] && left=$((30 * 86400))
  [ $(( na - $(date +%s) )) -ge "$left" ]
}
c_dns() {  # every name server for the pens zone answers for it with authority
  local ns out n=0
  for ns in $(dig +short +time=5 +tries=2 NS "$PENS_ZONE"); do
    out="$(dig +norec +time=5 +tries=2 @"$ns" SOA "$PENS_ZONE")" || return 1
    grep -q 'status: NOERROR' <<<"$out" && grep -Eq '^;; flags:[a-z ]* aa' <<<"$out" || return 1
    n=$((n + 1))
  done
  [ "$n" -gt 0 ]
}
c_pages() {  # WATCH_URLS: other pages that must answer, e.g. the sign-up page
  local u; for u in $WATCH_URLS; do curl -fsS -m 15 -o /dev/null "$u" || return 1; done
}
c_backup() { [ -n "$(find "$BACKUPS" -maxdepth 1 -name '*.tar.gz.age' -mmin -$((36 * 60)) 2>/dev/null | head -1)" ]; }

# A pen with public certificates gets them through the challenge DNS for its
# pens zone. Remember the zone, so this check still runs while the pen is down.
net="$(curl -fsS -m 15 "https://$HOST/hogman/v1/network" 2>/dev/null)"
if grep -q '"cert_mode":"public"' <<<"$net"; then
  z="$(sed -n 's/.*"zone":"\([a-z0-9.-]*\)".*/\1/p' <<<"$net")"
  [ -n "$z" ] && echo "${z#*.}" > "$STATE/pens-zone"
elif [ -n "$net" ]; then
  rm -f "$STATE/pens-zone"
fi
PENS_ZONE="$(cat "$STATE/pens-zone" 2>/dev/null)"

checks="headscale:Headscale is not answering on $HOST
pen:$HOST is not answering as a pen
cert:the certificate for $HOST is near expiry and not renewing (or can't be read)"
if [ -n "$PENS_ZONE" ]; then
  if command -v dig >/dev/null; then checks="$checks
dns:the challenge DNS for $PENS_ZONE isn't answering, so certificates can't renew"
  else log "dig not found; skipping the challenge DNS check"; fi
fi
[ -n "$BACKUPS" ] && checks="$checks
backup:no new backup in $BACKUPS for 36 hours"
[ -n "${WATCH_URLS:-}" ] && checks="$checks
pages:one of these isn't answering: $WATCH_URLS"

now=$(date +%s)
while IFS=: read -r name what; do
  f="$STATE/$name"
  if "c_$name"; then
    if [ -f "$f.alerted" ]; then
      push "✅ Hogman: $name OK" "Fixed. It was: $what." default white_check_mark
      log "$name recovered"
    fi
    rm -f "$f.fails" "$f.alerted"
  else
    n=$(( $(cat "$f.fails" 2>/dev/null || echo 0) + 1 )); echo "$n" > "$f.fails"
    log "$name failed ($n in a row)"
    last=$(cat "$f.alerted" 2>/dev/null || echo 0)
    if [ "$n" -ge 2 ] && [ $((now - last)) -ge $((6 * 3600)) ]; then
      push "🚨 Hogman: $name" "$what. (Checked from $(hostname -s), $n times in a row.)" high rotating_light \
        && echo "$now" > "$f.alerted"
    fi
  fi
done <<<"$checks"
