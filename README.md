# contract

`github.com/openctemio/contract` holds the contracts between the OpenCTEM
platform and its sensors: what a sensor can do, which options a tool takes,
how settings are signed and layered, how a run reports its outcome, how
politely it treats a target, and how scan data moves between them.

It is not a data format. The data format is [CTIS](https://github.com/openctemio/ctis),
a pure document standard. The packages here are the orchestration side: the
platform and the sensor SDK import them; a producer that only writes CTIS
documents does not need them.

The root module has no dependencies outside the Go standard library (CI
checks this).

## Packages

| Package | What it is |
|---|---|
| `capability` | The capability taxonomy: phases, typed ports, tier floors, standard params, and the output each capability must produce. `Check` tests a decoded CTIS document against a capability's contract. |
| `tooloption` | The shared vocabulary of tool execution options (timeout, rate, concurrency, retries), defined once for tools, the sensor SDK and the platform. |
| `settings` | The tool settings contract: the schema a tool declares for its configuration, and the layered values a scan runs with. |
| `outcome` | The per-target outcome of a scan task: how each target ended, so the platform settles finished targets and hands out only the rest. |
| `politeness` | The per-host politeness keys of scan work: which hosts a job touches and when two jobs conflict. |
| `edgeprotect` | Recognises answers that came from an edge protection (CDN or WAF) instead of the service. |
| `addrscope` | The one definition of an internal network address a shared scanner must never reach. |
| `identity` | How a scan's requests identify themselves: the bounds and validation of User-Agent values and rotation lists, and the one rule that picks a list value per scan run and target host (sticky per run and host, spread evenly), so the platform shows the value the sensor sends. |
| `ctlookup` | The contract of `lookup.ct@1`, the Certificate Transparency lookup a platform-owned sensor runs for the platform: the input (root domain, optional cursor), the typed answer (certificate records and per-source status), its bounds, and `Validate`, the one rule both sides apply (names bound to the queried domain, wildcard labels removed, unknown sources and states refused). |
| `secretref` | How a secret reaches a tool a sensor runs: the secret refs a signed job carries (kind, class, slot, audience, local policy), the sealed per-task fetch (request, answer, HPKE info), the value shapes and their validators, and the registry of third-party providers with the hosts each key may be sent to. |
| `source` | Where the code of a platform code scan comes from: repository, branch and exact commit. |
| `transfer` | A separate Go module, `github.com/openctemio/contract/transfer`: downloads files from an ordered list of origins, and the signed bundle format. It is separate because it depends on the Prometheus client, which the root module must not. |

## Relation to CTIS

Asset type names in `capability` (the `AssetType` constants and the
`carries` lists of the port types) follow CTIS 2.0. This module does not
import CTIS. A parity test in the platform checks these names, and the
JSON paths the capability rules require, against the CTIS 2.0 schema; it is
not repeated here. When CTIS adds an asset type, add the constant here and
update the parity test.

`capability.Check` takes the decoded JSON form of a CTIS document
(`map[string]any`), so no CTIS Go types are needed.

## Versioning

Semantic versioning, tags `vX.Y.Z`. The sensors and the platform are
upgraded together; there is no compatibility promise across major versions.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The OpenCTEM Contributor License
Agreement applies. Report security issues as in [SECURITY.md](SECURITY.md).

## License

Apache-2.0, see [LICENSE](LICENSE).
