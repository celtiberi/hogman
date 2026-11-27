#!/usr/bin/env bash
# Checks that the shell commands we show people (the join page's one-line
# commands and the README's) survive zsh, the default shell in macOS Terminal.
# Each command is run by zsh with curl, sh and the hogman binary replaced by
# no-ops, so only zsh's own word expansion is exercised.
set -euo pipefail
cd "$(dirname "$0")/../.."
command -v zsh >/dev/null || { echo "zsh is required" >&2; exit 1; }
command -v node >/dev/null || { echo "node is required" >&2; exit 1; }

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

# Import the join page's real command builders directly instead of scraping JS.
join_count=0
while IFS= read -r cmd || [ -n "$cmd" ]; do
  [ -n "$cmd" ] || continue
  join_count=$((join_count + 1))
  cmd="$(printf '%s' "$cmd" | sed -e 's|&& \./hogman .*|\&\& true|')"
  check "commands.js: $cmd" "$cmd"
done < <(node --input-type=module -e '
import { buildJoinCommands } from "./core/join-page/commands.js";
const host = process.argv[1];
const link = process.argv[2];
const shareLink = `${link}&for=share`;
for (const opts of [
  { host, cleanLink: link, forShare: false, isWork: false },
  { host, cleanLink: shareLink, forShare: true, isWork: false },
  { host, cleanLink: shareLink, forShare: true, isWork: true },
]) {
  const { startCmd, manualCmd } = buildJoinCommands(opts);
  console.log(startCmd);
  console.log(manualCmd);
}
' "$host" "$link")
if [ "$join_count" -eq 0 ]; then
  echo "FAIL commands.js: generated 0 commands" >&2
  fail=1
fi

# README code lines that start with "$ curl".
readme_count=0
while IFS= read -r line || [ -n "$line" ]; do
  [ -n "$line" ] || continue
  readme_count=$((readme_count + 1))
  cmd="$(printf '%s' "${line#\$ }" | sed -e "s|<your-pen>|example|g")"
  check "README: $cmd" "$cmd"
done < <(grep -E '^\$ curl ' README.md || true)
if [ "$readme_count" -eq 0 ]; then
  echo "FAIL README.md: extracted 0 '\$ curl ' commands" >&2
  fail=1
fi

[ "$fail" = 0 ] && echo "all user-facing commands run under zsh ($join_count commands.js, $readme_count README.md)"
exit "$fail"
