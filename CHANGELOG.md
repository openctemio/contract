# Changelog

All notable changes to this module. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.0.0] - 2026-11-03

First release. The packages moved out of the CTIS repository, with their history, when CTIS became a pure document format.

### Added: the orchestration packages

- `capability`, `tooloption`, `settings`, `outcome`, `politeness`, `edgeprotect`, `addrscope` and `source` in the root module `github.com/openctemio/contract`, with no dependency outside the standard library.
- `transfer` as the nested module `github.com/openctemio/contract/transfer`.

### Changed: no dependency on the CTIS document package

- `capability` declares its own `AssetType` names, which follow CTIS 2.0: `domain_name` (was `domain` and `subdomain`), `web_origin` (was `website` and `http_service`), `host` (was `server` and `compute`), `service` (was `open_port` and `service`), `identity` (was `iam_user`, `iam_role` and `service_account`), `kubernetes_cluster` (was `kubernetes`), `ip_range` (was `network`). `discovered_url` is gone; a crawl reports endpoints. `cloud_resource`, `container_image` and the other additive types are declared.
- `Capability.Check` takes a decoded JSON document (`map[string]any`) instead of a CTIS report value.
- Rule paths are checked for form only; the platform checks them against the CTIS schema.
