#!/usr/bin/env bash
# Prints the one-line join command exactly as the join page builds it
# (core/join-page/commands.js, buildStartCommand), for <host> and <link>.
#   core/test/render-join-cmd.sh <host> <link>
# The end-to-end test runs this text under zsh and bash, the way a person
# pastes it into a terminal.
set -euo pipefail
host="$1" link="$2"
here="$(cd "$(dirname "$0")/../.." && pwd)"
node --input-type=module -e '
import { pathToFileURL } from "node:url";
const { buildStartCommand } = await import(pathToFileURL(process.argv[1]).href);
process.stdout.write(buildStartCommand(process.argv[2], process.argv[3]) + "\n");
' "$here/core/join-page/commands.js" "$host" "$link"
