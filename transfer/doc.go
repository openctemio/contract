// Package transfer downloads files from an ordered list of origins (a
// release URL, mirrors, a local directory) with retries, resume and
// fall-back. It is the network half of the shared transfer layer for feeds
// (api docs/rfcs/RFC-070-chunked-feed-transfer.md); package
// transfer/bundle is the format and the consumer on top of it.
//
// Two kinds of file:
//
//   - Small: a mutable or signed file read into memory (a pointer, a key
//     set, a manifest), capped in size, fetched with a conditional GET when
//     a cache directory is configured (If-None-Match / 304).
//   - Blob: an immutable, content-addressed file (a chunk) named by its
//     sha256 and size. It is downloaded to <cache>/tmp, resumed with an
//     HTTP Range request after a dropped connection or a stall, verified
//     against the hash and size, and only then moved into <cache>/blobs. A
//     blob already in the cache is not downloaded again, which is how
//     chunks shared between releases are fetched once.
//
// Each origin is tried in order. Per origin, a transient failure (network
// error, stall, 408, 425, 429, 5xx) is retried with exponential back-off and
// jitter, honoring Retry-After up to a cap; a permanent one (404, other
// 4xx, a hash or size mismatch on a full download) moves to the next origin
// at once. An origin that keeps failing opens its circuit and is skipped for
// a cool-down. Mirrors cannot change content: blobs are hash-pinned and
// small files are signed and checked by the caller.
//
// Every HTTP request goes through the caller's client, which is required
// when an origin is a URL: pass an SSRF-guarded client (one that refuses
// private, loopback and link-local addresses at dial time). There is no
// unguarded default. File names are a single path element
// (no separators, no "..") so a name can never escape a local origin or the
// cache. Logs carry names, origins, sizes and errors, never content.
//
// The package is its own Go module (github.com/openctemio/ctis/transfer,
// tagged transfer/vX.Y.Z) so the ctis root module keeps zero external
// dependencies; it needs only the standard library and the Prometheus
// client. It is a contract: a feed publisher, the platform and any consumer
// share one implementation of the format without depending on the sensor
// SDK. It moved here unchanged from github.com/openctemio/sdk-go/pkg/transfer
// v0.1.0; a golden test pins the published bytes to that version.
//
// Stability: Experimental.
package transfer
