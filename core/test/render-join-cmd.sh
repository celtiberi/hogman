#!/usr/bin/env bash
# Prints the one-line join command exactly as the join page builds it
# (core/join-page/join.js, makeStartCmd), for <host> and <link>.
#   core/test/render-join-cmd.sh <host> <link>
# The end-to-end test runs this text under zsh and bash, the way a person
# pastes it into a terminal.
set -euo pipefail
host="$1" link="$2"
here="$(cd "$(dirname "$0")/../.." && pwd)"
tmpl="$(sed -n "s/^  const makeStartCmd = [a-z]* => \`\(.*\)\`;\$/\1/p" "$here/core/join-page/join.js")"
[ -n "$tmpl" ] || { echo "makeStartCmd not found in join.js" >&2; exit 1; }
printf '%s\n' "$tmpl" | sed -e "s|\${host}|$host|g" -e "s|\${quoted}|'$link'|g" -e 's|\${args ? .* : .*}||'
