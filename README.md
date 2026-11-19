# Hogman

A private internet you deploy yourself. One person runs a small server, invites whoever
they want, and the members get their own internet: names like `alice.bobo.hogman`,
HTTPS from the network's own certificate authority, and nothing visible from outside.
The owner can remove anyone within seconds.

- [DESIGN.md](DESIGN.md): the design, decisions and open questions
- [core/](core/): the deployable core node, registrar, join tool and end-to-end test

Built on Headscale, Tailscale, CoreDNS, step-ca and Caddy.

## Status

**Experimental.** Hogman is young security software. It has not been audited, and it has
not yet run on a public server. Try it, break it, tell us what you find. Don't trust it
with anything that matters yet.

## License

Hogman's code is free software under the [GNU Affero General Public License v3.0](LICENSE)
(AGPL-3.0). You may use, study, change and share it. If you run a changed version as a
service for others, you must offer them your changes under the same license.

The artwork in `site/public/` (the paintings and the logo) is not covered by that
license. All rights reserved.
