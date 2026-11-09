# Feed Adapters — Shodan / Censys / abuse.ch / AlienVault OTX

Threat-intel feed clients wired into the same gated chain as every
scanner. There is no privileged path for "just an API lookup":

```
typed MCP call (intel-feed family) → policy (deny-by-default)
  → budget/scope (tokens · rate · CIDR · kill switch)
  → adapter (typed args, value-aware flag allowlists)
  → hardened container command → candidate findings ONLY
```

## Adapters (`backend/g9_backend/tools/feed_adapters.py`)

| tool | typed call | API key handling | notes |
|---|---|---|---|
| `shodan` | `shodan host <target>` | `SHODAN_API_KEY` env name only | host lookup, `--history` allowlisted |
| `censys` | `censys host <target>` | `CENSYS_API_ID` + `CENSYS_API_SECRET` env names only | `--max-records` allowlisted |
| `abusech` | `abusech feed <feed> search <target>` | none (free feeds) | feed ∈ {urlhaus, threatfox, malwarebazaar, feodo, sslbl, yaraify}; flags refused |
| `otx` | `otx indicators <target>` | `OTX_API_KEY` env name only | `--limit`, `--section` allowlisted |

## Hard rules encoded (test-proven in `tests/test_feed_adapters.py`)

1. **Secrets never enter the command line.** `build_command(env_var_names=[...])`
   passes environment variable *names* only (`-e SHODAN_API_KEY`); docker inherits
   the values from the host environment. A name containing `=` or a value is
   refused at command build time — no key can reach the audit ledger or logs.
2. **Targets only from the authorized target_set** (rule 5). Each feed query is
   scoped to exactly one authorized IP/domain; agents cannot fish internet-wide
   queries through these adapters.
3. **Raw shell strings rejected** at the `intel-feed` MCP family contract boundary.
4. **Feed results are hypotheses** — candidate findings only, never verified
   results (Verification Authority doctrine unchanged).
5. **abuse.ch is metadata-level only**: scoped indicator/feed queries against
   authorized targets, consistent with the monitor-only governance of the
   sensitive intel categories in `intel/sources.py`.

## Registry & admission

`shodan` and `censys` were already in the arsenal registry
(`attack-surface-intel`, service class, "API key admission"). This stage adds
`abusech` and `otx` as `cti-feed` service-class entries with no special proof
gates (free, metadata-level). API keys themselves are recorded at operator
admission on the host — never in the repo, never in a spec, never in argv.

## Client image

All four adapters build commands against a single pinned client image
(`g9/feed-client:latest`) that reads its key from the container environment and
emits JSON to stdout for the evidence collector. The image is built and pinned
at admission on the G9 host, same as every other container image.
