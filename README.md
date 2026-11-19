# Hogman

A private internet you deploy yourself. One person runs a small server, invites whoever
they want, and the members get their own internet: names like `alice.bobo.hogman`,
HTTPS from the network's own certificate authority, and nothing visible from outside.
The owner can remove anyone within seconds.

- [DESIGN.md](DESIGN.md): the design, decisions and open questions
- [core/](core/): the deployable core node, registrar, join tool and end-to-end test

Built on Headscale, Tailscale, CoreDNS, step-ca and Caddy.
