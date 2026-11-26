#!/usr/bin/env bash
# Checks that the shell commands we show people (the join page's one-line
# commands and the README's) survive zsh, the default shell in macOS Terminal.
# Each command is run by zsh with curl, sh and the hogman binary replaced by
# no-ops, so only zsh's own word expansion is exercised.
set -euo pipefail
cd "$(dirname "$0")/../.."
command -v zsh >/dev/null || { echo "zsh is required" >&2; exit 1; }

host=example.gate.hogman.network
link="https://$host/join#k=hskey-auth-TEST"
fail=0
check() {  # check <label> <command>
  local label="$1" cmd="$2"
  # pipefail: a failure on the left of "| sh" must not be hidden by sh's
  # result; any zsh complaint on stderr also counts as a failure.
  if out="$(zsh -fc "setopt pipefail; curl() { :; }; sh() { :; }; chmod() { :; }; $cmd" 2>&1)" && [ -z "$out" ]; then
    echo "ok   $label"
  else
    echo "FAIL $label: $out"; echo "     $cmd"; fail=1
  fi
}

# The join page builds its commands from these templates.
while IFS= read -r tmpl; do
  cmd="$(printf '%s' "$tmpl" \
    | sed -e "s|\${host}|$host|g" -e "s|\${quoted}|'$link'|g" \
          -e 's|\${args ? .* : .*}||' -e 's|\${verb}||g' \
          -e 's|&& \./hogman .*|\&\& true|')"
  check "join.js: ${cmd:0:60}" "$cmd"
done < <(sed -n "s/^  const make[A-Za-z]*Cmd = [a-z]* => \`\(.*\)\`;\$/\1/p" core/join-page/join.js)

# README code lines that start with "$ curl".
while IFS= read -r line; do
  cmd="$(printf '%s' "${line#\$ }" | sed -e "s|<your-pen>|example|g")"
  check "README: ${cmd:0:60}" "$cmd"
done < <(grep -E '^\$ curl ' README.md)

[ "$fail" = 0 ] && echo "all user-facing commands run under zsh"
exit "$fail"
