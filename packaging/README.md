# Client Packaging

Hogman publishes standalone, SLSA-attested `hogman` client binaries and
`hogman-SHA256SUMS` on each immutable GitHub Release
(`celtiberi/hogman/releases/tag/v<version>`).

- `homebrew/hogman.rb.tmpl`: Homebrew formula installing `hogman`.
- `winget/Celtiberi.Hogman.yaml.tmpl`: WinGet portable manifest installing `hogman`.

When installed via Homebrew, Scoop, WinGet, or an OS package under `/usr/bin`,
`hogman update` detects the package manager and prints its upgrade command
instead of overwriting the managed binary in place.
