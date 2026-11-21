# Infrastructure as code

Decision D-23: DNS, cloud accounts and server setup change only through this folder, reviewed
in a PR and applied by CI. Nobody types into a dashboard, and no person or bot holds a write
token.

## DNS (`infra/dns`, dnscontrol)

- `dnsconfig.js` is every record in `hogman.network`.
- **A pull request** that touches it runs **dns preview**, which shows exactly what would
  change. It uses a read-only token from the `infra-preview` environment.
- **Merging to main** runs **dns apply** from the locked `infra` environment. It waits for
  @patrick's approval, runs only from `main`, and uses the edit token. Apply stays off until
  the repository variable `DNS_APPLY_ENABLED` is `true`.

### Keys

Two Cloudflare API tokens, each limited to the `hogman.network` zone:

| GitHub secret | Environment | Cloudflare permissions |
|---|---|---|
| `CLOUDFLARE_DNS_READ_TOKEN` | `infra-preview` | Zone → DNS → Read, Zone → Zone → Read |
| `CLOUDFLARE_DNS_EDIT_TOKEN` | `infra` | Zone → DNS → Edit, Zone → Zone → Read |

They're stored only as GitHub environment secrets, typed straight in with
`gh secret set … --env …` and never pasted anywhere else.

### Starting out

1. Run the **dns** workflow by hand with action **import**. It prints the live zone as
   dnscontrol config.
2. Copy those records into `dnsconfig.js` in a PR. Its preview must say **no changes**.
3. Merge, then set `DNS_APPLY_ENABLED=true`. Remove `NO_PURGE` in a later, reviewed PR, once
   we're sure the file holds every record.
