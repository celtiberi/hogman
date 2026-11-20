# Sourced by core/test/run.sh and deploy/test-host.sh. They share one Docker
# and fixed names (hogman-front, pen-bobo, port 3478...), so only one may run
# at a time on a machine. A lock left by a run that died is taken over.
E2E_LOCK=/tmp/hogman-e2e.lock

e2e_lock() {
  local pid said=""
  until mkdir "$E2E_LOCK" 2>/dev/null; do
    pid="$(cat "$E2E_LOCK/pid" 2>/dev/null || true)"
    if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then rm -rf "$E2E_LOCK"; continue; fi
    # No pid (another tool's lock, or one that died mid-write): give it two hours.
    if [ -z "$pid" ] && [ -n "$(find "$E2E_LOCK" -maxdepth 0 -mmin +120 2>/dev/null)" ]; then rm -rf "$E2E_LOCK"; continue; fi
    [ -n "$said" ] || { echo "waiting for another end-to-end run (pid ${pid:-?}) to finish..." >&2; said=1; }
    sleep 10
  done
  echo $$ > "$E2E_LOCK/pid"
}

e2e_unlock() {
  [ "$(cat "$E2E_LOCK/pid" 2>/dev/null)" = "$$" ] && rm -rf "$E2E_LOCK"
  return 0
}
