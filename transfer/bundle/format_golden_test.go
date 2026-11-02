package bundle

import (
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// goldenBundleDigest pins the published bytes of a deterministic release:
// every chunk, the signed manifest and the signed pointer, hashed in name
// order. The value was produced by the writer this package was moved from
// (github.com/openctemio/sdk-go/pkg/transfer/bundle v0.1.0), so a bundle
// written here is byte-identical to one a v0.1.0 publisher writes and
// existing consumers and caches keep working. A change to the format, the
// chunking or the signing shows up here; it needs a new schema version, not
// a new golden value.
//
// The chunks are gzip at BestCompression and the deflate encoder of the Go
// standard library is not a stable format: Go 1.27 emits different (equally
// valid) compressed bytes than Go 1.22 to 1.26 for the same input, which
// changes the chunk names, the manifest and the signatures. Nothing in the
// writer can pin that: the gzip header is already fixed (no name, no mtime)
// and the level is explicit. So the byte-for-byte pin is kept per encoder
// generation, selected by a probe of the running toolchain's encoder, and the
// encoder-independent content is pinned for every toolchain (see
// goldenContentDigest). A published bundle is never rebuilt by consumers,
// which verify the signature over the bytes they receive.
const goldenBundleDigest = "b1ae109bb4baee26e8865fcaaed0cc17f8bf395983bdb67aea97573a08d76bd2"

// goldenBundleDigestByEncoder maps the probe digest of a deflate encoder
// generation (deflateProbe) to the bundle digest it produces.
var goldenBundleDigestByEncoder = map[string]string{
	// Go 1.22 to 1.26: the encoder the v0.1.0 writer used.
	"5d403b20bfc1": goldenBundleDigest,
	// Go 1.27.
	"48986c9d6bbe": "30931f6cf27c65962efa95862a725941c7161c2139f08a47fe5f045a18f24a84",
}

// goldenContentDigest pins what the chunks decompress to, independent of the
// compressor: the sorted digests of every chunk's JSON Lines bytes.
const goldenContentDigest = "2e93b34c35f231c1b1c00dc2fe02dd4a51a4bd3f905e55d0244a4f482c60e7a9"

// deflateProbe identifies the running toolchain's gzip encoder generation by
// compressing a fixed input at the level the writer uses.
func deflateProbe() string {
	var in bytes.Buffer
	for i := range 5000 {
		_, _ = fmt.Fprintf(&in, `{"id":"alpha-%04d","n":%d,"tags":["alpha","golden"]}`+"\n", i, i*7919%1000)
	}
	var out bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&out, gzip.BestCompression)
	_, _ = zw.Write(in.Bytes())
	_ = zw.Close()
	sum := sha256.Sum256(out.Bytes())
	return hex.EncodeToString(sum[:])[:12]
}

func TestBundleBytesMatchGolden(t *testing.T) {
	dir := t.TempDir()
	signer := Ed25519Signer{Key: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))}
	w, err := NewWriter(dir, WriterOptions{Feed: "goldenfeed", Sequence: 3, Kind: KindSnapshot, TargetRecords: 40})
	if err != nil {
		t.Fatal(err)
	}
	for _, stream := range []string{"alpha", "beta"} {
		if err := w.Stream(stream); err != nil {
			t.Fatal(err)
		}
		for i := range 150 {
			id := fmt.Sprintf("%s-%04d", stream, i)
			b, _ := json.Marshal(map[string]any{"id": id, "n": i, "tags": []string{stream, "golden"}})
			if err := w.Add(id, b); err != nil {
				t.Fatal(err)
			}
		}
	}
	created := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	_, ref, err := w.Finish(json.RawMessage(`{"source":"golden"}`), created, created.Add(7*24*time.Hour), signer)
	if err != nil {
		t.Fatal(err)
	}
	if err := WritePointer(dir, Pointer{Feed: "goldenfeed", Sequence: 3, Snapshot: ref,
		CreatedAt: created, ExpiresAt: created.Add(7 * 24 * time.Hour)}, signer); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.Type().IsRegular() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	h := sha256.New()
	for _, n := range names {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(b)
		_, _ = fmt.Fprintf(h, "%s %x\n", n, sum)
	}
	var contents []string
	for _, n := range names {
		if !strings.HasSuffix(n, ".jsonl.gz") {
			continue
		}
		f, err := os.Open(filepath.Join(dir, n))
		if err != nil {
			t.Fatal(err)
		}
		zr, err := gzip.NewReader(f)
		if err != nil {
			_ = f.Close()
			t.Fatal(err)
		}
		raw, err := io.ReadAll(zr)
		_ = f.Close()
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		contents = append(contents, hex.EncodeToString(sum[:]))
	}
	sort.Strings(contents)
	ch := sha256.Sum256([]byte(strings.Join(contents, "\n")))
	if got := hex.EncodeToString(ch[:]); got != goldenContentDigest {
		t.Fatalf("chunk contents drifted: %d chunks, digest %s, want %s", len(contents), got, goldenContentDigest)
	}

	got := hex.EncodeToString(h.Sum(nil))
	probe := deflateProbe()
	want, known := goldenBundleDigestByEncoder[probe]
	if !known {
		t.Logf("unknown deflate encoder %s: bundle digest %s, byte-for-byte pin skipped, chunk contents verified", probe, got)
		return
	}
	if got != want {
		t.Fatalf("bundle bytes drifted from the v0.1.0 writer: %d files, digest %s, want %s (encoder %s)", len(names), got, want, probe)
	}
}
