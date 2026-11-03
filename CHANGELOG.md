# Changelog

All notable changes to this module. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
