// Package tart implements a puller for Tart-format OCI images
// (ghcr.io/cirruslabs/macos-*) that produces the same on-disk layout
// macOS-vz-kubelet expects from its native (agoda) image format.
//
// Tart schema reference: ../../../../TART_SCHEMA.md
// Compatibility plan:    ../../../../COMPATIBILITY_ANALYSIS.md
package tart

// Tart OCI media types. Source of truth:
//   upstreams/tart/Sources/tart/OCI/Manifest.swift
const (
	MediaTypeConfig       = "application/vnd.cirruslabs.tart.config.v1"
	MediaTypeDiskV2       = "application/vnd.cirruslabs.tart.disk.v2"
	MediaTypeDiskV1Legacy = "application/vnd.cirruslabs.tart.disk.v1"
	MediaTypeNVRAM        = "application/vnd.cirruslabs.tart.nvram.v1"

	// Per-layer annotations on disk.v2 layers.
	AnnotationUncompressedSize   = "org.cirruslabs.tart.uncompressed-size"
	AnnotationUncompressedDigest = "org.cirruslabs.tart.uncompressed-content-digest"
)

// TartConfig is the JSON payload of a cirruslabs.tart.config.v1 layer.
// Fields we don't use are deliberately omitted; JSON decoding tolerates extras.
type TartConfig struct {
	Version       int    `json:"version"`
	Arch          string `json:"arch"`
	OS            string `json:"os"`
	DiskFormat    string `json:"diskFormat"`
	HardwareModel string `json:"hardwareModel"` // base64 bplist (VZMacHardwareModel.dataRepresentation)
	ECID          string `json:"ecid"`          // base64 bplist (VZMacMachineIdentifier.dataRepresentation)
	// Informational only; CPU/RAM come from Pod spec:
	CPUCount      int   `json:"cpuCount"`
	CPUCountMin   int   `json:"cpuCountMin"`
	MemorySize    int64 `json:"memorySize"`
	MemorySizeMin int64 `json:"memorySizeMin"`
}

// IsTartManifest reports whether an OCI manifest's layer media types indicate
// a Tart-format image. It is true if at least one layer uses a
// cirruslabs.tart.* media type. Callers should sniff before calling into
// the native oci.Store puller.
func IsTartManifest(layerMediaTypes []string) bool {
	for _, mt := range layerMediaTypes {
		switch mt {
		case MediaTypeConfig, MediaTypeDiskV2, MediaTypeDiskV1Legacy, MediaTypeNVRAM:
			return true
		}
	}
	return false
}
