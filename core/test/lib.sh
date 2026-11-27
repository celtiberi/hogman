# Shared helpers for core/test/*.sh E2E suites.
# Sourced by run.sh, acme-pebble.sh, and sidecar-check.sh.

test_goarch() {
  case "$(uname -m)" in
    x86_64|amd64) echo amd64 ;;
    aarch64|arm64) echo arm64 ;;
    *) echo "" ;;
  esac
}

pull_retry() {
  local img="$1" i
  for i in 1 2 3; do
    docker image inspect "$img" >/dev/null 2>&1 && return 0
    docker pull -q "$img" >/dev/null && return 0
    echo "docker pull $img failed (attempt $i/3); retrying..." >&2
    sleep 2
  done
  docker pull -q "$img" >/dev/null
}

# gen_pebble_certs <dir> <ca_cn> <server_cn> <san_list> [days]
# Generates a throwaway ECDSA P-256 CA and server keypair for offline Pebble
# (and mock429) HTTPS endpoints. Leaves certs world-readable (0644) for
# unprivileged containers such as Caddy.
gen_pebble_certs() {
  local dir="$1" ca_cn="$2" srv_cn="$3" san="$4" days="${5:-7}"
  mkdir -p "$dir"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$dir/ca.key" -out "$dir/ca.crt" \
    -days "$days" -subj "/CN=$ca_cn" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1

  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$dir/server.key" -out "$dir/server.csr" \
    -subj "/CN=$srv_cn" >/dev/null 2>&1

  cat >"$dir/ext.cnf" <<EOF
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=${san}
EOF

  openssl x509 -req -in "$dir/server.csr" \
    -CA "$dir/ca.crt" -CAkey "$dir/ca.key" -CAcreateserial \
    -out "$dir/server.crt" -days "$days" \
    -extfile "$dir/ext.cnf" >/dev/null 2>&1

  chmod 644 "$dir/ca.crt" "$dir/server.crt" "$dir/server.key"
}

# Assertion and retry helpers used by core/test/run.sh and its phase scripts.
# Callers maintain `pass`, `fail`, and `WORK`.
step()  { echo; echo "== $*"; }

check() {   # check <description> <command...>
  local d="$1" log="$WORK/.check.out"; shift
  if "$@" >"$log" 2>&1; then
    echo "  PASS  $d"
    pass=$((pass + 1))
  else
    echo "  FAIL  $d"
    fail=$((fail + 1))
    [ -s "$log" ] && tail -n 5 "$log" | sed 's/^/        | /'
  fi
}

retry() {   # retry <seconds> <command...>
  local n="$1"; shift
  for _ in $(seq "$n"); do
    "$@" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

timed() {   # timed <var> <seconds> <command...>: retry, store elapsed seconds in <var>
  local var="$1" n="$2" t0 rc; shift 2
  t0="$(date +%s)"
  retry "$n" "$@"
  rc=$?
  printf -v "$var" '%s' "$(( $(date +%s) - t0 ))"
  return $rc
}

not() { ! "$@"; }

# Capture command stdout before grepping: under pipefail, piping docker exec /
# curl directly into `grep -q` closes the pipe on the first match and makes the
# producer exit 255/141 (EPIPE/SIGPIPE).
match() {    # match <grep-pattern> <command...>
  local pat="$1" out; shift
  out="$("$@")" || return 1
  grep -q -- "$pat" <<<"$out"
}

no_match() { # no_match <grep-pattern> <command...>: command succeeds and stdout does not match
  local pat="$1" out; shift
  out="$("$@")" || return 1
  ! grep -q -- "$pat" <<<"$out"
}
