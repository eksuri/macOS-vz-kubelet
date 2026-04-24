package tart

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestDecodeLZ4Block_RoundTrip_Random(t *testing.T) {
	src := make([]byte, 1<<20) // 1 MiB random → nearly incompressible
	if _, err := rand.Read(src); err != nil {
		t.Fatal(err)
	}
	compressed, err := EncodeLZ4Block(src)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	out, err := DecodeLZ4Block(compressed, int64(len(src)))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(src, out) {
		t.Fatal("round-trip mismatch on random data")
	}
}

func TestDecodeLZ4Block_RoundTrip_Repetitive(t *testing.T) {
	src := bytes.Repeat([]byte("abcdefgh"), 64*1024) // 512 KiB repeating
	compressed, err := EncodeLZ4Block(src)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if len(compressed) >= len(src)/2 {
		t.Logf("weak compression: %d/%d — acceptable, still validates correctness", len(compressed), len(src))
	}
	out, err := DecodeLZ4Block(compressed, int64(len(src)))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(src, out) {
		t.Fatal("round-trip mismatch on repetitive data")
	}
}

func TestDecodeLZ4Block_RoundTrip_ZerosLikeDisk(t *testing.T) {
	// Real Tart chunks are full of zero runs (macOS disk has lots of free
	// space). Exercise the zero-run path.
	src := make([]byte, 512*1024)
	for i := 0; i < len(src); i += 4096 {
		// Sprinkle some non-zero data every 4K to simulate a live filesystem.
		if i%65536 == 0 {
			copy(src[i:], []byte("data-block"))
		}
	}
	compressed, err := EncodeLZ4Block(src)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	out, err := DecodeLZ4Block(compressed, int64(len(src)))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(src, out) {
		t.Fatal("round-trip mismatch on zero-heavy data")
	}
}

func TestDecodeLZ4Block_WrongSize(t *testing.T) {
	src := []byte("hello world, this is a test payload for lz4 decode")
	compressed, err := EncodeLZ4Block(src)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	_, err = DecodeLZ4Block(compressed, int64(len(src)+10))
	if err == nil {
		t.Fatal("expected size-mismatch error, got nil")
	}
}

func TestIsTartManifest(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want bool
	}{
		{"tart sonoma-like", []string{MediaTypeConfig, MediaTypeDiskV2, MediaTypeDiskV2, MediaTypeNVRAM}, true},
		{"agoda native", []string{
			"application/vnd.agoda.macosvz.config.v1+json",
			"application/vnd.agoda.macosvz.disk.image.v1",
			"application/vnd.agoda.macosvz.aux.image.v1",
		}, false},
		{"empty", nil, false},
		{"legacy v1", []string{MediaTypeDiskV1Legacy}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := IsTartManifest(c.in); got != c.want {
				t.Errorf("got %v want %v", got, c.want)
			}
		})
	}
}

func TestValidateTartConfig(t *testing.T) {
	good := &TartConfig{
		Version: 1, Arch: "arm64", OS: "darwin", DiskFormat: "raw",
		HardwareModel: "aGk=", ECID: "aGk=",
	}
	if err := validateTartConfig(good); err != nil {
		t.Fatalf("good config rejected: %v", err)
	}

	cases := []*TartConfig{
		{Version: 2, Arch: "arm64", OS: "darwin", HardwareModel: "a", ECID: "b"},
		{Version: 1, Arch: "x86_64", OS: "darwin", HardwareModel: "a", ECID: "b"},
		{Version: 1, Arch: "arm64", OS: "linux", HardwareModel: "a", ECID: "b"},
		{Version: 1, Arch: "arm64", OS: "darwin", DiskFormat: "qcow2", HardwareModel: "a", ECID: "b"},
		{Version: 1, Arch: "arm64", OS: "darwin", HardwareModel: "", ECID: "b"},
		{Version: 1, Arch: "arm64", OS: "darwin", HardwareModel: "a", ECID: ""},
	}
	for i, bad := range cases {
		if err := validateTartConfig(bad); err == nil {
			t.Errorf("case %d: bad config accepted: %+v", i, bad)
		}
	}
}
