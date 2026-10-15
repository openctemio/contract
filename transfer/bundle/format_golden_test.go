package bundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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
const goldenBundleDigest = "b1ae109bb4baee26e8865fcaaed0cc17f8bf395983bdb67aea97573a08d76bd2"

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
	if got := hex.EncodeToString(h.Sum(nil)); got != goldenBundleDigest {
		t.Fatalf("bundle bytes drifted from the v0.1.0 writer: %d files, digest %s, want %s", len(names), got, goldenBundleDigest)
	}
}
