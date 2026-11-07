# Changelog

All notable changes to this module. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.6.0] - 2026-11-07

### Added: identity package (User-Agent rotation)

- New package `identity`: `CheckUserAgent` and `CheckUserAgents` (1 to 256 printable ASCII characters, no line break, no leading or trailing space; at most 200 values, none twice), `CheckKey`, `CanonicalHost`, and `SelectIndex` / `SelectUserAgent`, the rule that picks one value of a rotation list per (scan run key, target host).
- The choice is sticky (every request of a run to a host carries the same value, whatever the port, scheme or case) and spreads runs and hosts evenly (HMAC-SHA-256 keyed by the run key over a fixed label and the canonical host). The rule is versioned by its label; a test pins its output.
- Additive: no existing package changes.

## [1.5.1] - 2026-11-05

### Fixed: release of 1.5.0

- The v1.5.0 tag points at a commit without its changelog section, so its release was not published. 1.5.1 has the same code; use 1.5.1.

## [1.5.0] - 2026-11-05

### Changed: capture.screenshot@1 is routed

- `capture.screenshot@1` goes from `planned` to `routed` (tier 1, phase `discover.active`). The act is stated: a headless browser loads a web origin with GET and HEAD only, to the job's targets and web scope only, with no WebSocket or WebRTC connection and no download, under a time budget, and the picture is capped in pixels and size.
- It reports on its input origin (`extra_outputs: asset:web_origin`, no output port of its own): the origin's `properties.web_evidence` (the platform's web evidence shape). Outputs select `assets[type=web_origin]` with `value` and `properties.web_evidence`; `web_application` is no longer named (no implementation emits it).
- Params: `page_timeout` (5-60 seconds), `full_page` (boolean), `max_requests` (10-500 per page). The major stays 1 (contract versions stay v1 before 1.0); the capability had no implementation.

## [1.4.0] - 2026-11-05

### Changed: service detection is routed

- `detect.services@1` goes from planned to routed (tier 1, phase `discover.active`, still major 1). Credential-free handshakes on known open ports only: the server's first bytes, protocol greetings and a TLS handshake, never a login, bind or state-changing command, never a range. Params: `ports` (port_list filter), `transports` (`tcp`, `udp`; tcp when unset, udp is opt-in), `depth` (`fast`, `thorough`; fast when unset), `rate` (1-1000 services per second), `timeout_ms` (100-10000). Outputs unchanged: a `service` asset with `value` and an application protocol or a product.

## [1.3.1] - 2026-11-05

### Security: webpath deny paths hold for every spelling a server reads

- `Denied` reads a deny path both as written and percent-decoded: an exclusion stored as `/files/My%20Docs` now denies `/files/My Docs/a.bak` (before, an escaped deny path never matched, since requests are compared decoded).
- `Denied` reads a `*` segment of a deny path as any one segment, as the platform's path exclusions do: `/tenants/*/admin` denies `/tenants/acme/admin/x` (before, `*` was compared literally).
- Paths are compared case-folded to ASCII (U+017F is `s`, U+212A is `k`), with trailing dots and spaces of each segment dropped (`/admin./x` is `/admin/x`), and `Readings` adds the path a server that decodes twice sees (`/%252e%252e/admin`). `Under` must hold for that reading too.
- `CleanDeny`: the stored form of a deny path (decoded and cleaned like a request path; dot segments and encoded separators refused).
- `CheckCandidate`: a guessed candidate path may hold no `%25` and no byte outside ASCII, raw or decoded.

## [1.3.0] - 2026-11-05

### Added: package webpath, the one reading of a web request path

- `CleanPath`: the path a server sees (percent-decoded, backslashes as slashes, dot segments resolved); encoded slashes, backslashes and NUL, control characters and `..;` are refused.
- `Readings`, `Denied` (case-insensitive prefix, over-blocking on purpose, every reading incl. the one without `;params`) and `Under` (segment boundary): the platform filters planned paths and the sensor's web scope refuses requests with the same code.
- `Destructive` and `DestructiveVerbs`: a path that names a state-changing action (`/logout`, `/log-out`, `/admin/deleteUser`, `/resetPassword`) is never requested by discovery and never followed by a crawler.

### Added: web path discovery capabilities

- `enumerate.web_paths@1` (routed, tier 1, phase `discover.active`): request platform-supplied candidate paths on a web origin with GET or HEAD only and report the ones that answer differently from the origin's calibrated not-found response, as endpoints with status, content type, size and a body hash (never the body). Params: `lists` (`derived`, `s`, `m`, `l`), `extensions` (`auto`, `none`, `backup`), `max_requests_per_origin` (50-100000), `rate` (1-50 requests per second), `exclude_paths`. There is no recursion param: the platform plans each level.
- `enumerate.web_params@1` (later, tier 2): reserved for query parameter discovery; not runnable, and its params may change before the first implementation.

## [1.2.0] - 2026-11-05

### Added: package secretref, the contract of task secrets

- `Set` and `Ref`: the secret refs a signed job carries in its payload member `secrets` (names only, never values), each with a kind, a class (`provider` or `target`, by what the value opens), the tool slot it fills, its audience (where the value may be sent), its consumer (the tool or the egress forwarder) and its local policy (`allow`, `never`, `only`). At most 64 refs.
- Kinds `provider_key` (a third-party source key; class provider, audience the provider's registry hosts) and `egress_proxy` (the job's proxy pool credentials; forwarder only, never local). Target kinds use the same shape: a target credential fills a slot and goes to the task's targets only.
- The fetch: `FetchRequest` (lease epoch, refs, single-use reply key, inside the signed body), `SealedAnswer` (HPKE suite 1, key id, sealed bytes), `Info` (the HPKE info binding sensor, command, epoch and request body), `Answer` and `Answer.Check` (the sensor's check of an opened answer).
- The provider registry (`providers.json`): every provider's key format, the hosts a tool sends its key to, and for keys that name their endpoint, the anchored host rule. `Provider.ValidateKey` is the one key validator of the platform and the sensor; `Provider.Audience` gives the hosts a key may reach. Errors never repeat a key.

## [1.1.1] - 2026-11-03

### Fixed: two output rules still named 1.x members

- `scan.ports`: one rule, service assets with `technical.service.port` and `technical.service.transport`. The `ip_ports` shape (ports grouped under `technical.ip_address.ports[]`) is removed, since CTIS 2.0 has no such member; the remaining rule has no shape name.
- `check.tls`: `technical.certificate.sha256_fingerprint` (was `fingerprint`).

## [1.1.0] - 2026-11-03

### Changed: capability output rules name CTIS 2.0 members

The output rules no longer require opaque `properties` keys (CTIS 2.0 gives `properties` no meaning) or removed 1.x members:

- `discover.subdomains`: `value` (the root domain is derived by the receiver).
- `monitor.web_content`: `extensions` (the captures are `extensions["io.openctem"].web_content`).
- `intel.passive`: `source_refs` instead of `properties.source`.
- `lookup.asn` ranges: `technical.ip_address.asn`.
- `discover.hosts`: `last_seen_at` instead of `properties.live_by`.
- `scan.ports` shape `open_port_assets`: `technical.service.port` and `technical.service.transport` (the host is in the service value `host:port/transport`).
- service detection: `technical.service.app_protocol` or `technical.service.product`.
- `probe.http`: `technical.http.status_code`; technology detection: `technologies`; `capture.screenshot` (planned): `value`.
- Findings: `asset_value` and `vulnerability.cve_id` removed from the rules (`asset_ref` is required in 2.0; `vulnerability.ids`); `evidence` is `evidence_items`.

## [transfer 1.0.1] - 2026-11-03

### Fixed: go directive of the transfer module

- `github.com/openctemio/contract/transfer` declares `go 1.26.0`, the minimum its dependencies need (1.0.0 declared 1.27.0, which forced consumers on Go 1.26 to upgrade). CI tests it on Go 1.26 and 1.27 and refuses a `go` directive newer than the consumers' Go.

## [1.0.0] - 2026-11-03

First release. The packages moved out of the CTIS repository, with their history, when CTIS became a pure document format.

### Added: the orchestration packages

- `capability`, `tooloption`, `settings`, `outcome`, `politeness`, `edgeprotect`, `addrscope` and `source` in the root module `github.com/openctemio/contract`, with no dependency outside the standard library.
- `transfer` as the nested module `github.com/openctemio/contract/transfer`.

### Changed: no dependency on the CTIS document package

- `capability` declares its own `AssetType` names, which follow CTIS 2.0: `domain_name` (was `domain` and `subdomain`), `web_origin` (was `website` and `http_service`), `host` (was `server` and `compute`), `service` (was `open_port` and `service`), `identity` (was `iam_user`, `iam_role` and `service_account`), `kubernetes_cluster` (was `kubernetes`), `ip_range` (was `network`). `discovered_url` is gone; a crawl reports endpoints. `cloud_resource`, `container_image` and the other additive types are declared.
- `Capability.Check` takes a decoded JSON document (`map[string]any`) instead of a CTIS report value.
- Rule paths are checked for form only; the platform checks them against the CTIS schema.
