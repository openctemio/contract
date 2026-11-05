# Capability taxonomy v1

Generated from `capability/taxonomy.json` by `capability.Markdown()`. Do not edit by hand: run `go test ./capability -run TestMarkdownIsCurrent -update`.

A capability is an act a scan tool performs. The capability carries the phase, the tier floor, the typed ports, the standard params, the required CTIS output and the framework references; a tool only declares which capabilities it implements. A tool's effective tier is the highest of the capability's floor, the tool's own request and the platform's classification.

## Phases

| Phase | CTEM stage | Meaning |
|---|---|---|
| `discover.passive` | discovery | No packet to the target: third-party data and DNS. |
| `discover.active` | discovery | Enumerates the live surface: ports, HTTP services, crawling. |
| `assess` | discovery | Finds weaknesses on known surface: templates, DAST, SAST, SCA, IaC, posture. |
| `validate` | validation | Proves exploitability or reachability, or retests a finding. |
| `collect` | discovery | Pulls assets and findings from another product or a file. |

## Port types

| Port | Label | CTIS asset types |
|---|---|---|
| `root_domain` | Root domain | `domain_name` |
| `hostname` | Hostname | `domain_name` |
| `ip` | IP address | `ip_address`, `host` |
| `cidr` | Network range | `ip_range`, `subnet` |
| `service` | Service (host:port) | `service` |
| `url` | URL | `web_origin`, `api`, `web_application` |
| `repository` | Repository | `repository` |
| `container_image` | Container image | `container_image`, `container` |
| `cloud_account` | Cloud account | `cloud_account` |
| `finding` | Finding | none |
| `endpoint` | Web endpoint (method and path) | none |

## Capabilities

| Capability | Status | Phase | Tier floor | In | Out | ATT&CK | D3FEND |
|---|---|---|---|---|---|---|---|
| [`discover.subdomains@1`](#discoversubdomains1) | routed | discover.passive | T0 | `root_domain` | `hostname` | T1596.001, T1590.002, T1593.002 | D3-AI |
| [`enumerate.subdomains@1`](#enumeratesubdomains1) | routed | discover.active | T1 | `root_domain` | `hostname` | T1590.002, T1595.003 | D3-NM |
| [`enumerate.web_paths@1`](#enumerateweb_paths1) | routed | discover.active | T1 | `url` | `endpoint` | T1595.003 | D3-AI |
| [`enumerate.web_params@1`](#enumerateweb_params1) | later | discover.active | T2 | `endpoint` | `endpoint` | T1595.003 | D3-AI |
| [`monitor.web_content@1`](#monitorweb_content1) | routed | discover.active | T1 | `url` | none | T1594 | - |
| [`intel.passive@1`](#intelpassive1) | planned | discover.passive | T0 | `root_domain`, `ip`, `cidr` | `hostname`, `cidr`, `ip` | T1596.002, T1596.003, T1596.005 | D3-AI, D3-NM |
| [`resolve.dns@1`](#resolvedns1) | routed | discover.passive | T0 | `hostname` | `hostname`, `ip` | T1590.002 | D3-NM |
| [`lookup.rdap@1`](#lookuprdap1) | routed | discover.passive | T0 | `root_domain` | `root_domain` | T1596.002, T1590.001 | D3-AI |
| [`lookup.asn@1`](#lookupasn1) | routed | discover.passive | T0 | `ip`, `cidr` | `ip`, `cidr` | T1590.005, T1596.002 | D3-AI, D3-NM |
| [`discover.hosts@1`](#discoverhosts1) | routed | discover.active | T1 | `ip`, `cidr` | `ip` | T1595.001, T1018 | D3-NM |
| [`scan.ports@1`](#scanports1) | routed | discover.active | T1 | `hostname`, `ip` | `service`, `ip` | T1595.001, T1046 | D3-NM |
| [`detect.services@1`](#detectservices1) | routed | discover.active | T1 | `service` | `service` | T1595.001, T1592.002 | D3-SWI |
| [`probe.http@1`](#probehttp1) | routed | discover.active | T1 | `hostname`, `ip`, `service`, `url` | `url`, `ip` | T1595, T1594 | D3-AI |
| [`fingerprint.tech@1`](#fingerprinttech1) | planned | discover.active | T1 | `url`, `service` | `url`, `service` | T1592.002 | D3-SWI |
| [`check.tls@1`](#checktls1) | planned | assess | T1 | `service`, `url` | `finding` | T1596.003 | D3-CI |
| [`capture.screenshot@1`](#capturescreenshot1) | routed | discover.active | T1 | `url` | none | T1594 | - |
| [`crawl.web@1`](#crawlweb1) | routed | discover.active | T1 | `url` | `url`, `endpoint` | T1594, T1595.003 | D3-AI |
| [`discover.cloud@1`](#discovercloud1) | planned | discover.passive | T0 | `cloud_account` | `cloud_account` | T1580, T1526 | D3-AI |
| [`discover.repositories@1`](#discoverrepositories1) | later | discover.passive | T0 | none | `repository` | T1593.003 | D3-AI |
| [`vuln.templates@1`](#vulntemplates1) | routed | assess | T1 | `url`, `service`, `hostname`, `ip`, `endpoint` | `finding` | T1595.002, T1190 | D3-AVE, D3-NVA |
| [`dast.web@1`](#dastweb1) | routed | assess | T2 | `url`, `endpoint` | `finding` | T1595.002, T1190 | D3-AVE |
| [`sast.code@1`](#sastcode1) | routed | assess | T0 | `repository` | `finding` | T1190 | D3-AVE |
| [`secrets.code@1`](#secretscode1) | routed | assess | T0 | `repository` | `finding` | T1552.001 | D3-CI |
| [`sca.deps@1`](#scadeps1) | routed | assess | T0 | `repository`, `container_image` | `finding` | T1195.001 | D3-SWI, D3-AVE |
| [`sbom.generate@1`](#sbomgenerate1) | planned | assess | T0 | `repository`, `container_image` | none | T1195.001 | D3-SWI |
| [`iac.misconfig@1`](#iacmisconfig1) | routed | assess | T0 | `repository` | `finding` | - | D3-CI |
| [`container.image@1`](#containerimage1) | routed | assess | T0 | `container_image` | `finding` | T1195.002 | D3-AVE |
| [`cloud.posture@1`](#cloudposture1) | planned | assess | T0 | `cloud_account` | `finding` | T1580 | D3-CI |
| [`config.benchmark@1`](#configbenchmark1) | later | assess | T1 | `ip`, `hostname`, `cloud_account` | `finding` | - | D3-CI |
| [`host.credentialed@1`](#hostcredentialed1) | planned | assess | T1 | `ip`, `hostname` | `finding` | T1078 | D3-AVE |
| [`network_va.connector@1`](#network_vaconnector1) | routed | collect | T1 | `ip`, `cidr` | `finding` | T1595.002 | D3-NVA |
| [`verify.finding@1`](#verifyfinding1) | planned | validate | T0 | `finding` | `finding` | - | D3-AVE |
| [`check.takeover@1`](#checktakeover1) | planned | validate | T1 | `hostname` | `finding` | T1584.001 | D3-CI |
| [`check.credentials@1`](#checkcredentials1) | later | validate | T0 | none | `finding` | T1589.001, T1078 | - |
| [`simulate.attack@1`](#simulateattack1) | later | validate | T2 | `ip`, `hostname` | `finding` | - | - |
| [`import.file@1`](#importfile1) | routed | collect | T0 | none | `finding` | - | - |
| [`import.api_spec@1`](#importapi_spec1) | planned | collect | T0 | none | `endpoint` | - | - |

### discover.subdomains@1

Subdomain discovery: Find subdomains of a root domain from passive sources.

- Status: routed; phase `discover.passive` (CTEM discovery); tier floor T0.
- Ports: in `root_domain`, out `hostname`.
- References: ATT&CK T1596.001, T1590.002, T1593.002; D3FEND D3-AI; CAPEC-169.

| Param | Type | Values | Description |
|---|---|---|---|
| `sources` | string_list |  | Passive sources to query; empty means the tool's defaults. |
| `recursive` | boolean |  | Also enumerate subdomains of found subdomains. |
| `max_results` | integer | 1..5000 | Stop after this many names per root domain. |

Required output (every selected record):

- `assets[type=domain_name]` carries `value`.

### enumerate.subdomains@1

Subdomain enumeration: Find subdomains of a root domain by actively querying DNS for candidate names (a wordlist of labels), keeping only the names that resolve.

- Status: routed; phase `discover.active` (CTEM discovery); tier floor T1.
- Ports: in `root_domain`, out `hostname`.
- References: ATT&CK T1590.002, T1595.003; D3FEND D3-NM; CAPEC-309.

| Param | Type | Values | Description |
|---|---|---|---|
| `method` | string | `bruteforce`, `permutations` | How candidate names are made. |
| `wordlist` | string | `s`, `m`, `l` | Size class of the label list the platform supplies. |
| `max_queries` | integer | 1..10000000 | Send at most this many DNS queries per root domain. |
| `recursive_depth` | integer | 0..2 | Also enumerate under the names found, this many levels deep. |

Required output (every selected record):

- `assets[type=domain_name]` carries `value`.

### enumerate.web_paths@1

Web path discovery: Request candidate paths on a web origin with GET or HEAD only, and report the ones that answer differently from the origin's calibrated not-found response. The platform supplies the candidates; the tool never adds paths, never follows redirects and never sends a body. Reports endpoints with status, content type, size and a body hash, never the body.

- Status: routed; phase `discover.active` (CTEM discovery); tier floor T1.
- Ports: in `url`, out `endpoint`.
- References: ATT&CK T1595.003; D3FEND D3-AI; CAPEC-87.

| Param | Type | Values | Description |
|---|---|---|---|
| `lists` | string_list | `derived`, `s`, `m`, `l` | Candidate lists the platform supplies: derived (built from the tenant's own inventory) and the size classes of the path wordlist. |
| `extensions` | string | `auto`, `none`, `backup` | File extensions added to candidate names: chosen from the origin's technologies, none, or backup extensions only. |
| `max_requests_per_origin` | integer | 50..100000 | Send at most this many requests to one origin, calibration included. |
| `rate` | integer | 1..50 | Requests per second to one origin, at most. |
| `exclude_paths` | string_list |  | Paths never requested, with every path under them. |

Required output (every selected record):

- `endpoints` carries `origin`, `path`, `status_code`.

### enumerate.web_params@1

Web parameter discovery: Request known endpoints with candidate query parameter names carrying random alphanumeric values, and report the names that change or are reflected in the response. Reserved: the contract may change before the first implementation.

- Status: later; phase `discover.active` (CTEM discovery); tier floor T2.
- Ports: in `endpoint`, out `endpoint`.
- References: ATT&CK T1595.003; D3FEND D3-AI.

Required output (every selected record):

- `endpoints` carries `origin`, `path`, `params[].name`.

### monitor.web_content@1

Web content monitoring: Fetch listed URLs and report the response (status, type, size, SHA-256 and a capped body) so the platform can detect page and script changes. Nothing is executed.

- Status: routed; phase `discover.active` (CTEM discovery); tier floor T1.
- Ports: in `url`, out none.
- Also emits: `asset:web_origin`.
- References: ATT&CK T1594.

Required output (every selected record):

- `assets[type=web_origin]` carries `value`, `extensions`.

### intel.passive@1

Passive intelligence: Names, ranges and addresses from certificate transparency and passive DNS data.

- Status: planned; phase `discover.passive` (CTEM discovery); tier floor T0.
- Ports: in `root_domain`, `ip`, `cidr`, out `hostname`, `cidr`, `ip`.
- References: ATT&CK T1596.002, T1596.003, T1596.005; D3FEND D3-AI, D3-NM; CAPEC-169.

Required output (every selected record):

- `assets` carries `value`, `source_refs`.

### resolve.dns@1

DNS resolution: Resolve names to addresses and aliases.

- Status: routed; phase `discover.passive` (CTEM discovery); tier floor T0.
- Ports: in `hostname`, out `hostname`, `ip`.
- References: ATT&CK T1590.002; D3FEND D3-NM; CAPEC-309.

| Param | Type | Values | Description |
|---|---|---|---|
| `record_types` | string_list | `a`, `aaaa`, `cname`, `mx`, `ns`, `txt` | DNS record types to query. |
| `wildcard_filter` | boolean |  | Drop names that only resolve through a wildcard record. |

Required output (every selected record):

- `assets[type=domain_name]` carries `value`, `technical.domain.dns_records[].type`, `technical.domain.dns_records[].value`.

### lookup.rdap@1

Domain registration lookup: Registrar, registrant organization, name servers and registration dates of a root domain, from the RDAP service of its registry.

- Status: routed; phase `discover.passive` (CTEM discovery); tier floor T0.
- Ports: in `root_domain`, out `root_domain`.
- References: ATT&CK T1596.002, T1590.001; D3FEND D3-AI; CAPEC-169.

| Param | Type | Values | Description |
|---|---|---|---|
| `follow_registrar` | boolean |  | Also ask the registrar RDAP service the registry answer links to (registrant details a thin registry does not hold). |

Required output (every selected record):

- `assets[type=domain_name]` carries `value`, `technical.domain.whois`.

### lookup.asn@1

Network ownership lookup: Origin autonomous system, its holder and the announced range of an address or network, from public routing data; optionally the other ranges the same system announces.

- Status: routed; phase `discover.passive` (CTEM discovery); tier floor T0.
- Ports: in `ip`, `cidr`, out `ip`, `cidr`.
- References: ATT&CK T1590.005, T1596.002; D3FEND D3-AI, D3-NM; CAPEC-169.

| Param | Type | Values | Description |
|---|---|---|---|
| `include_announced` | boolean |  | Also report the other ranges the origin system announces, as discovered networks. |
| `max_ranges` | integer | 1..5000 | Report at most this many announced ranges per autonomous system. |

Required output (every selected record):

- `assets[type=ip_address]` carries `value`, `technical.ip_address.asn`.
- `assets[type=ip_range]` carries `value`, `technical.ip_address.asn`.

### discover.hosts@1

Host discovery: Find the live addresses of a range or an address list with light probes (ICMP echo or a TCP connection to a few common ports), before deeper scans.

- Status: routed; phase `discover.active` (CTEM discovery); tier floor T1.
- Ports: in `ip`, `cidr`, out `ip`.
- References: ATT&CK T1595.001, T1018; D3FEND D3-NM; CAPEC-292.

| Param | Type | Values | Description |
|---|---|---|---|
| `ports` | port_list |  | TCP ports a host is probed on; a host that answers on any of them is live. |
| `rate` | integer | 1..100000 | Maximum probes per second. |

Required output (every selected record):

- `assets[type=ip_address]` carries `value`, `last_seen_at`.

### scan.ports@1

Port scan: Find open TCP ports (connect scan).

- Status: routed; phase `discover.active` (CTEM discovery); tier floor T1.
- Ports: in `hostname`, `ip`, out `service`, `ip`.
- References: ATT&CK T1595.001, T1046; D3FEND D3-NM; CAPEC-300.

| Param | Type | Values | Description |
|---|---|---|---|
| `ports` | port_list |  | Ports and port ranges to scan. |
| `top_n` | integer | 1..65535 | Scan the N most common ports instead of a list. |
| `protocol` | string | `tcp` | Transport protocol. |
| `rate` | integer | 1..100000 | Maximum requests per second. |

Required output (every selected record):

- `assets[type=service]` carries `value`, `technical.service.port`, `technical.service.transport`.

### detect.services@1

Service detection: Identify the service, product and version behind a known open port with credential-free handshakes: read what the server sends first, send protocol greetings and a TLS handshake, never a login, bind or state-changing command. Targets are the job's host:port services, never ranges. Reports each service with the same value as the input port, its application protocol, product, version and CPE when the handshake gives them, a bounded banner, TLS, and anonymous access only when the handshake itself proves it.

- Status: routed; phase `discover.active` (CTEM discovery); tier floor T1.
- Ports: in `service`, out `service`.
- References: ATT&CK T1595.001, T1592.002; D3FEND D3-SWI; CAPEC-541.

| Param | Type | Values | Description |
|---|---|---|---|
| `ports` | port_list |  | Only probe services on these ports and port ranges; others are skipped. |
| `transports` | string_list | `tcp`, `udp` | Transports to probe (default tcp); udp is opt-in. |
| `depth` | string | `fast`, `thorough` | fast (default): what the server sends first and the probes for the port's usual protocols; thorough: also the other credential-free probes, bounded per port. |
| `rate` | integer | 1..1000 | Services started per second, at most. |
| `timeout_ms` | integer | 100..10000 | Timeout of one connection in milliseconds. |

Required output (every selected record):

- `assets[type=service]` carries `value` and at least one of `technical.service.app_protocol`, `technical.service.product`.

### probe.http@1

HTTP probe: Probe web services: status, title, technologies, TLS certificate.

- Status: routed; phase `discover.active` (CTEM discovery); tier floor T1.
- Ports: in `hostname`, `ip`, `service`, `url`, out `url`, `ip`.
- Also emits: `asset:certificate`, `endpoint`.
- References: ATT&CK T1595, T1594; D3FEND D3-AI; CAPEC-541.

| Param | Type | Values | Description |
|---|---|---|---|
| `ports` | port_list |  | Ports to probe when the input is a hostname or an address. |
| `follow_redirects` | boolean |  | Follow redirects on the same host. |
| `tech_detect` | boolean |  | Detect the technologies a page uses. |
| `tls_grab` | boolean |  | Record the TLS certificate. |
| `api_schema` | boolean |  | Fetch API schema documents (OpenAPI, GraphQL introspection) at well-known paths and report their operations as endpoints. |

Required output (every selected record):

- `assets[type=web_origin]` carries `value`, `technical.http.status_code`.

### fingerprint.tech@1

Technology fingerprint: Identify the technologies a web service or service runs.

- Status: planned; phase `discover.active` (CTEM discovery); tier floor T1.
- Ports: in `url`, `service`, out `url`, `service`.
- References: ATT&CK T1592.002; D3FEND D3-SWI; CAPEC-541.

Required output (every selected record):

- `assets[type=web_origin|service]` carries `value`, `technologies`.

### check.tls@1

TLS check: Check certificates, protocols and ciphers.

- Status: planned; phase `assess` (CTEM discovery); tier floor T1.
- Ports: in `service`, `url`, out `finding`.
- Also emits: `asset:certificate`.
- References: ATT&CK T1596.003; D3FEND D3-CI.

Required output (every selected record):

- `assets[type=certificate]` carries `value`, `technical.certificate.sha256_fingerprint`, `technical.certificate.not_after`.

### capture.screenshot@1

Screenshot: Load a web origin in a headless browser and report a picture of the page with its status, title, server and final URL, as the origin's web evidence. The browser sends GET and HEAD only, to the job's targets and web scope only, opens no WebSocket or WebRTC connection, downloads nothing and changes nothing on the target; the page has a time budget and the picture is capped in pixels and size.

- Status: routed; phase `discover.active` (CTEM discovery); tier floor T1.
- Ports: in `url`, out none.
- Also emits: `asset:web_origin`.
- References: ATT&CK T1594.

| Param | Type | Values | Description |
|---|---|---|---|
| `page_timeout` | integer | 5..60 | Seconds one page may take to load before its scripts are stopped and the picture is taken. |
| `full_page` | boolean |  | Capture the page from its top down to 2400 pixels instead of the viewport. |
| `max_requests` | integer | 10..500 | Most requests one page may make (the page itself, its scripts, styles and images); later ones are refused. |

Required output (every selected record):

- `assets[type=web_origin]` carries `value`, `properties.web_evidence`.

### crawl.web@1

Web crawl: Crawl web services for URLs, staying on the same host. Reports endpoints.

- Status: routed; phase `discover.active` (CTEM discovery); tier floor T1.
- Ports: in `url`, out `url`, `endpoint`.
- References: ATT&CK T1594, T1595.003; D3FEND D3-AI.

| Param | Type | Values | Description |
|---|---|---|---|
| `depth` | integer | 1..10 | Maximum crawl depth. |
| `js_parse` | boolean |  | Parse JavaScript for endpoints. |
| `max_urls` | integer | 1..5000 | Stop after this many URLs per start URL. |

Required output (every selected record):

- `endpoints` carries `origin`, `path`.

### discover.cloud@1

Cloud resource discovery: List the resources of a cloud account through its read-only API.

- Status: planned; phase `discover.passive` (CTEM discovery); tier floor T0.
- Ports: in `cloud_account`, out `cloud_account`.
- Also emits: `asset:host`, `asset:cloud_resource`, `asset:storage`, `asset:database`, `asset:serverless`, `asset:container_registry`, `asset:kubernetes_cluster`, `asset:load_balancer`, `asset:vpc`, `asset:subnet`, `asset:firewall`, `asset:identity`.
- References: ATT&CK T1580, T1526; D3FEND D3-AI.

| Param | Type | Values | Description |
|---|---|---|---|
| `regions` | string_list |  | Only these regions; empty means every region the account uses. |

Required output (every selected record):

- `assets[type=host|cloud_resource|storage|database|serverless|container_registry|kubernetes_cluster|load_balancer|vpc|subnet|firewall]` carries `value`, `technical.cloud.provider`, `technical.cloud.resource_id`.

### discover.repositories@1

Repository discovery: List the repositories of a source-code organisation.

- Status: later; phase `discover.passive` (CTEM discovery); tier floor T0.
- Ports: in none, out `repository`.
- References: ATT&CK T1593.003; D3FEND D3-AI.

Required output (every selected record):

- `assets[type=repository]` carries `value`, `technical.repository.default_branch`.

### vuln.templates@1

Vulnerability templates: Run non-intrusive vulnerability templates.

- Status: routed; phase `assess` (CTEM discovery); tier floor T1.
- Ports: in `url`, `service`, `hostname`, `ip`, `endpoint`, out `finding`.
- References: ATT&CK T1595.002, T1190; D3FEND D3-AVE, D3-NVA.

| Param | Type | Values | Description |
|---|---|---|---|
| `severity` | string_list | `info`, `low`, `medium`, `high`, `critical`, `unknown` | Only templates of these severities. |
| `tags` | string_list |  | Only templates with these tags. |
| `exclude_tags` | string_list |  | Skip templates with these tags. |
| `rate` | integer | 1..100000 | Maximum requests per second. |

Required output (every selected record):

- `findings` carries `rule_id`, `severity`, `title` and at least one of `network.host`, `asset_ref`, `location.path`, `web.url`.

### dast.web@1

Web application scan: Dynamic application security testing of a web application, or of the known endpoints of one.

- Status: routed; phase `assess` (CTEM discovery); tier floor T2.
- Ports: in `url`, `endpoint`, out `finding`.
- References: ATT&CK T1595.002, T1190; D3FEND D3-AVE.

| Param | Type | Values | Description |
|---|---|---|---|
| `profile` | string | `crawl_only`, `high_risk`, `full` | Scan depth. |
| `max_duration_minutes` | integer | 1..1440 | Stop the scan after this many minutes. |

Required output (every selected record):

- `findings` carries `rule_id`, `severity`, `title` and at least one of `network.host`, `asset_ref`, `web.url`.

### sast.code@1

Static analysis: Static application security testing of source code.

- Status: routed; phase `assess` (CTEM discovery); tier floor T0.
- Ports: in `repository`, out `finding`.
- References: ATT&CK T1190; D3FEND D3-AVE.

| Param | Type | Values | Description |
|---|---|---|---|
| `languages` | string_list |  | Only analyze these languages. |

Required output (every selected record):

- `findings` carries `rule_id`, `severity`, `title`, `location.path`.

### secrets.code@1

Secrets in code: Find committed secrets in a repository.

- Status: routed; phase `assess` (CTEM discovery); tier floor T0.
- Ports: in `repository`, out `finding`.
- Finding types: `secret`.
- References: ATT&CK T1552.001; D3FEND D3-CI.

| Param | Type | Values | Description |
|---|---|---|---|
| `history` | boolean |  | Scan the commit history, not only the current tree. |

Required output (every selected record):

- `findings` carries `rule_id`, `title`, `location.path`, `secret.masked_value`.

### sca.deps@1

Dependency scan: Find vulnerable dependencies and build a component inventory.

- Status: routed; phase `assess` (CTEM discovery); tier floor T0.
- Ports: in `repository`, `container_image`, out `finding`.
- Also emits: `dependency`.
- Finding types: `vulnerability`.
- References: ATT&CK T1195.001; D3FEND D3-SWI, D3-AVE.

| Param | Type | Values | Description |
|---|---|---|---|
| `dev_deps` | boolean |  | Include development dependencies. |

Required output (every selected record):

- `dependencies` carries `name`, `version`.
- `findings` carries `severity`, `title` and at least one of `vulnerability.ids`, `rule_id`.

### sbom.generate@1

Software bill of materials: Build the component inventory of a repository or an image, without vulnerability matching.

- Status: planned; phase `assess` (CTEM discovery); tier floor T0.
- Ports: in `repository`, `container_image`, out none.
- Also emits: `dependency`.
- References: ATT&CK T1195.001; D3FEND D3-SWI.

| Param | Type | Values | Description |
|---|---|---|---|
| `dev_deps` | boolean |  | Include development dependencies. |

Required output (every selected record):

- `dependencies` carries `name`, `version`.

### iac.misconfig@1

Infrastructure-as-code misconfiguration: Find misconfigurations in infrastructure-as-code files.

- Status: routed; phase `assess` (CTEM discovery); tier floor T0.
- Ports: in `repository`, out `finding`.
- Finding types: `misconfiguration`.
- References: D3FEND D3-CI.

| Param | Type | Values | Description |
|---|---|---|---|
| `frameworks` | string_list |  | Only these IaC frameworks. |

Required output (every selected record):

- `findings` carries `rule_id`, `severity`, `title`, `location.path`.

### container.image@1

Container image scan: Find vulnerabilities in a container image.

- Status: routed; phase `assess` (CTEM discovery); tier floor T0.
- Ports: in `container_image`, out `finding`.
- Also emits: `dependency`.
- References: ATT&CK T1195.002; D3FEND D3-AVE.

| Param | Type | Values | Description |
|---|---|---|---|
| `os_pkgs` | boolean |  | Include operating-system packages. |

Required output (every selected record):

- `findings` carries `severity`, `title` and at least one of `vulnerability.ids`, `rule_id`.

### cloud.posture@1

Cloud posture: Read-only configuration review of a cloud account.

- Status: planned; phase `assess` (CTEM discovery); tier floor T0.
- Ports: in `cloud_account`, out `finding`.
- Finding types: `misconfiguration`, `compliance`.
- References: ATT&CK T1580; D3FEND D3-CI.

Required output (every selected record):

- `findings` carries `rule_id`, `severity`, `title`.

### config.benchmark@1

Configuration benchmark: Check a host or an account against a configuration benchmark.

- Status: later; phase `assess` (CTEM discovery); tier floor T1.
- Ports: in `ip`, `hostname`, `cloud_account`, out `finding`.
- Finding types: `compliance`, `misconfiguration`.
- References: D3FEND D3-CI.

Required output (every selected record):

- `findings` carries `rule_id`, `severity`, `title`, `compliance.framework`, `compliance.control_id`.

### host.credentialed@1

Credentialed host scan: Authenticated vulnerability scan of a host.

- Status: planned; phase `assess` (CTEM discovery); tier floor T1.
- Ports: in `ip`, `hostname`, out `finding`.
- References: ATT&CK T1078; D3FEND D3-AVE.

Required output (every selected record):

- `findings` carries `severity`, `title` and at least one of `rule_id`, `vulnerability.ids`.

### network_va.connector@1

Network vulnerability assessment (connector): Run a network vulnerability scan through a connected scanner product.

- Status: routed; phase `collect` (CTEM discovery); tier floor T1.
- Ports: in `ip`, `cidr`, out `finding`.
- References: ATT&CK T1595.002; D3FEND D3-NVA.

| Param | Type | Values | Description |
|---|---|---|---|
| `policy` | string |  | Scan policy name in the connected product. |

Required output (every selected record):

- `findings` carries `rule_id`, `severity`, `title` and at least one of `network.host`, `asset_ref`.

### verify.finding@1

Verify a finding: Retest a finding with a tool that can reproduce it. A web finding is retested at its finding.web location (URL, method, parameter). Used by retests, not as a workflow node.

- Status: planned; phase `validate` (CTEM validation); tier floor T0; cross-cutting (not a workflow node).
- Ports: in `finding`, out `finding`.
- References: D3FEND D3-AVE.

| Param | Type | Values | Description |
|---|---|---|---|
| `mode` | string | `retest`, `exploit_check` | retest re-runs the rule that found it; exploit_check runs a safe proof without side effects. |

### check.takeover@1

Subdomain takeover check: Find names whose alias points at an unclaimed third-party resource.

- Status: planned; phase `validate` (CTEM validation); tier floor T1.
- Ports: in `hostname`, out `finding`.
- References: ATT&CK T1584.001; D3FEND D3-CI.

Required output (every selected record):

- `findings` carries `rule_id`, `severity`, `title`, `evidence_items` and at least one of `network.host`, `asset_ref`.

### check.credentials@1

Credential exposure check: Look up exposed credentials of the organisation in breach corpora; never a login attempt.

- Status: later; phase `validate` (CTEM validation); tier floor T0.
- Ports: in none, out `finding`.
- References: ATT&CK T1589.001, T1078.

Required output (every selected record):

- `findings` carries `rule_id`, `severity`, `title`.

### simulate.attack@1

Attack simulation: Run attack scenarios on a host and report whether controls prevented or detected them.

- Status: later; phase `validate` (CTEM validation); tier floor T2.
- Ports: in `ip`, `hostname`, out `finding`.

Required output (every selected record):

- `findings` carries `rule_id`, `severity`, `title`.

### import.file@1

Import a file: Read a report file of a known format (SARIF, CycloneDX, SPDX, Nessus, ...) into assets, findings and dependencies. Makes no network connection.

- Status: routed; phase `collect` (CTEM discovery); tier floor T0; cross-cutting (not a workflow node).
- Ports: in none, out `finding`.
- Also emits: `asset:*`, `dependency`.

| Param | Type | Values | Description |
|---|---|---|---|
| `format` | string |  | The file format; empty means detect it. |

### import.api_spec@1

Import an API specification: Read an API specification (OpenAPI, GraphQL schema, Postman collection) into the endpoints of an origin. Makes no connection to the target.

- Status: planned; phase `collect` (CTEM discovery); tier floor T0; cross-cutting (not a workflow node).
- Ports: in none, out `endpoint`.

Required output (every selected record):

- `endpoints` carries `origin`, `path`, `method`.
