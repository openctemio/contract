# Changelog

All notable changes to this module. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.3.0] - 2026-11-05

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
