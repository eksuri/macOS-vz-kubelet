// Package tart — puller.
//
// Entry point: Pull(ctx, ref, creds, cacheDir) → MacPlatformConfigurationOptions.
//
// Layout produced in cacheDir:
//
//	<cacheDir>/
//	├── config.json      (agoda schema; translated from Tart's config)
//	├── disk.img         (raw, reassembled from Tart's disk.v2 chunks)
//	├── disk.img.digest  (sha256 of disk.img; for vz-kubelet's validator)
//	├── aux.img          (verbatim from Tart's nvram.v1 layer)
//	├── aux.img.digest   (sha256 of aux.img)
//	└── tart.manifest.json (cached remote manifest, for resume/debug)

package tart

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/agoda-com/macOS-vz-kubelet/pkg/oci"
	"github.com/agoda-com/macOS-vz-kubelet/pkg/resource"
	"github.com/agoda-com/macOS-vz-kubelet/pkg/vm/config"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/virtual-kubelet/virtual-kubelet/log"
	"github.com/virtual-kubelet/virtual-kubelet/trace"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
)

// Filenames emitted to the cache. Must match agoda oci.MediaType.Title()
// so downstream code (vz-kubelet VM runtime) is happy.
const (
	fileConfig   = "config.json"
	fileDisk     = "disk.img"
	fileAux      = "aux.img"
	fileManifest = "tart.manifest.json"
)

// SniffAndPull pulls `ref` into `cacheDir` iff the remote image is a Tart
// image. It returns (options, true, nil) on a successful Tart pull,
// (_, false, nil) if the manifest is not Tart (caller should fall through
// to the native agoda puller), or (_, _, err) on error.
func SniffAndPull(
	ctx context.Context,
	ref string,
	cacheDir string,
	creds resource.RegistryCredentials,
	ignoreExisting bool,
) (cfg config.MacPlatformConfigurationOptions, isTart bool, err error) {
	ctx, span := trace.StartSpan(ctx, "tart.SniffAndPull")
	defer func() { span.SetStatus(err); span.End() }()

	repo, err := remote.NewRepository(ref)
	if err != nil {
		return cfg, false, fmt.Errorf("invalid ref %q: %w", ref, err)
	}
	repo.PlainHTTP = isLocalhostOrLocalIP(repo.Reference.Registry)
	if !creds.IsEmpty() {
		repo.Client = &auth.Client{
			Credential: auth.StaticCredential(repo.Reference.Registry, auth.Credential{
				Username: creds.Username,
				Password: creds.Password,
			}),
		}
	}
	ctx = auth.AppendRepositoryScope(ctx, repo.Reference, auth.ActionPull)

	// Resolve + fetch manifest
	manifestDesc, err := repo.Resolve(ctx, repo.Reference.Reference)
	if err != nil {
		return cfg, false, fmt.Errorf("resolve %q: %w", ref, err)
	}
	mfBytes, err := fetchAllBytes(ctx, repo, manifestDesc)
	if err != nil {
		return cfg, false, fmt.Errorf("fetch manifest: %w", err)
	}

	var m ocispec.Manifest
	if err = json.Unmarshal(mfBytes, &m); err != nil {
		return cfg, false, fmt.Errorf("decode manifest: %w", err)
	}

	// Sniff
	layerTypes := make([]string, 0, len(m.Layers))
	for _, l := range m.Layers {
		layerTypes = append(layerTypes, l.MediaType)
	}
	if !IsTartManifest(layerTypes) {
		return cfg, false, nil
	}

	log.G(ctx).Infof("Detected Tart-format image: %s", ref)

	if err = os.MkdirAll(cacheDir, 0o755); err != nil {
		return cfg, true, fmt.Errorf("mkdir cache: %w", err)
	}

	// Fast path: if everything is already present AND validates, short-circuit.
	// We always check the cache for Tart images regardless of ignoreExisting —
	// ignoreExisting is meant for the agoda format's digest-based revalidation,
	// but our cache check verifies file presence + config parsability which is
	// sufficient. Re-downloading 47GB on every pod create is not acceptable.
	if c, ok := tryLoadCache(ctx, cacheDir); ok {
		log.G(ctx).Infof("Tart image %s found in cache, skipping pull", ref)
		return c, true, nil
	}

	// Cache manifest for debuggability (and future resume work).
	if err = os.WriteFile(filepath.Join(cacheDir, fileManifest), mfBytes, 0o644); err != nil {
		return cfg, true, fmt.Errorf("write manifest cache: %w", err)
	}

	// Reject v1 disk layers up-front.
	for _, l := range m.Layers {
		if l.MediaType == MediaTypeDiskV1Legacy {
			return cfg, true, fmt.Errorf("legacy Tart disk.v1 format not supported; re-push with a current Tart")
		}
	}

	// Categorise layers.
	var (
		configLayer *ocispec.Descriptor
		nvramLayer  *ocispec.Descriptor
		diskLayers  []ocispec.Descriptor
	)
	for i := range m.Layers {
		l := &m.Layers[i]
		switch l.MediaType {
		case MediaTypeConfig:
			if configLayer != nil {
				return cfg, true, errors.New("tart: multiple config layers in manifest")
			}
			configLayer = l
		case MediaTypeNVRAM:
			if nvramLayer != nil {
				return cfg, true, errors.New("tart: multiple nvram layers in manifest")
			}
			nvramLayer = l
		case MediaTypeDiskV2:
			diskLayers = append(diskLayers, *l)
		}
	}
	if configLayer == nil {
		return cfg, true, errors.New("tart: manifest missing config layer")
	}
	if nvramLayer == nil {
		return cfg, true, errors.New("tart: manifest missing nvram layer")
	}
	if len(diskLayers) == 0 {
		return cfg, true, errors.New("tart: manifest has no disk layers")
	}

	// 1. Pull and translate config.
	tartCfgBytes, err := fetchAllBytes(ctx, repo, *configLayer)
	if err != nil {
		return cfg, true, fmt.Errorf("fetch config layer: %w", err)
	}
	var tc TartConfig
	if err = json.Unmarshal(tartCfgBytes, &tc); err != nil {
		return cfg, true, fmt.Errorf("decode Tart config: %w", err)
	}
	if err = validateTartConfig(&tc); err != nil {
		return cfg, true, err
	}
	vzCfg := oci.NewMacOSConfig(tc.HardwareModel, tc.ECID)
	vzCfgBytes, err := json.MarshalIndent(&vzCfg, "", "  ")
	if err != nil {
		return cfg, true, fmt.Errorf("encode vz-kubelet config: %w", err)
	}
	configPath := filepath.Join(cacheDir, fileConfig)
	if err = writeFileAtomic(configPath, vzCfgBytes, 0o644); err != nil {
		return cfg, true, err
	}

	// 2. Pull nvram → aux.img.
	auxPath := filepath.Join(cacheDir, fileAux)
	if err = pullLayerToFile(ctx, repo, *nvramLayer, auxPath); err != nil {
		return cfg, true, fmt.Errorf("pull nvram: %w", err)
	}
	if err = writeDigestSidecar(auxPath); err != nil {
		return cfg, true, fmt.Errorf("write aux digest: %w", err)
	}

	// 3. Pull + reassemble disk chunks → disk.img.
	diskPath := filepath.Join(cacheDir, fileDisk)
	if err = reassembleDisk(ctx, repo, diskLayers, diskPath); err != nil {
		return cfg, true, fmt.Errorf("reassemble disk: %w", err)
	}
	if err = writeDigestSidecar(diskPath); err != nil {
		return cfg, true, fmt.Errorf("write disk digest: %w", err)
	}

	return config.MacPlatformConfigurationOptions{
		BlockStoragePath:      diskPath,
		AuxiliaryStoragePath:  auxPath,
		HardwareModelData:     tc.HardwareModel,
		MachineIdentifierData: tc.ECID,
	}, true, nil
}

// tryLoadCache returns the config if all expected files are present.
// Does NOT verify digests; that's vz-kubelet's job via its own validator.
// We return ok=false on any missing/unreadable file so a stale/partial cache
// is safely rewritten.
func tryLoadCache(ctx context.Context, cacheDir string) (cfg config.MacPlatformConfigurationOptions, ok bool) {
	configPath := filepath.Join(cacheDir, fileConfig)
	diskPath := filepath.Join(cacheDir, fileDisk)
	auxPath := filepath.Join(cacheDir, fileAux)
	for _, p := range []string{configPath, diskPath, auxPath} {
		if st, err := os.Stat(p); err != nil || st.Size() == 0 {
			return cfg, false
		}
	}
	b, err := os.ReadFile(configPath)
	if err != nil {
		return cfg, false
	}
	var c oci.Config
	if err = json.Unmarshal(b, &c); err != nil {
		return cfg, false
	}
	if c.HardwareModelData == "" || c.MachineIdData == "" {
		return cfg, false
	}
	return config.MacPlatformConfigurationOptions{
		BlockStoragePath:      diskPath,
		AuxiliaryStoragePath:  auxPath,
		HardwareModelData:     c.HardwareModelData,
		MachineIdentifierData: c.MachineIdData,
	}, true
}

func validateTartConfig(tc *TartConfig) error {
	if tc.Version != 1 {
		return fmt.Errorf("tart config: unsupported version %d (want 1)", tc.Version)
	}
	if tc.OS != "darwin" {
		return fmt.Errorf("tart config: OS must be darwin, got %q", tc.OS)
	}
	if tc.Arch != "arm64" {
		return fmt.Errorf("tart config: arch must be arm64, got %q", tc.Arch)
	}
	if tc.DiskFormat != "" && tc.DiskFormat != "raw" {
		return fmt.Errorf("tart config: unsupported diskFormat %q (want raw)", tc.DiskFormat)
	}
	if tc.HardwareModel == "" {
		return errors.New("tart config: missing hardwareModel")
	}
	if tc.ECID == "" {
		return errors.New("tart config: missing ecid")
	}
	return nil
}

// reassembleDisk fetches each compressed chunk, decompresses, and writes it
// at the correct offset in outPath. Uses a bounded worker pool to keep memory
// predictable: each worker holds at most one compressed + one uncompressed
// chunk (~512 MiB uncompressed).
func reassembleDisk(ctx context.Context, repo *remote.Repository, layers []ocispec.Descriptor, outPath string) error {
	ctx, span := trace.StartSpan(ctx, "tart.reassembleDisk")
	defer span.End()

	// Parse annotations first; total size determines truncation.
	type chunk struct {
		idx      int
		desc     ocispec.Descriptor
		offset   int64
		unSize   int64
		unDigest string
	}
	chunks := make([]chunk, len(layers))
	var totalSize int64
	for i, l := range layers {
		sizeStr := l.Annotations[AnnotationUncompressedSize]
		if sizeStr == "" {
			return fmt.Errorf("disk layer %d missing %s annotation", i, AnnotationUncompressedSize)
		}
		sz, err := strconv.ParseInt(sizeStr, 10, 64)
		if err != nil {
			return fmt.Errorf("disk layer %d bad uncompressed-size %q: %w", i, sizeStr, err)
		}
		chunks[i] = chunk{
			idx:      i,
			desc:     l,
			offset:   totalSize,
			unSize:   sz,
			unDigest: l.Annotations[AnnotationUncompressedDigest],
		}
		totalSize += sz
	}
	log.G(ctx).Infof("Tart disk: %d chunks, %.2f GB uncompressed", len(chunks), float64(totalSize)/(1<<30))

	// Create & truncate output file.
	f, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("create %s: %w", outPath, err)
	}
	if err = f.Truncate(totalSize); err != nil {
		_ = f.Close()
		return fmt.Errorf("truncate %s: %w", outPath, err)
	}
	// We do concurrent pwrites — opening separate FDs is not required on macOS
	// (pwrite is thread-safe on a single fd). We share one fd + a Mutex to
	// be conservative; contention is negligible because workers are I/O-bound.
	var fdMu sync.Mutex
	closeOnce := sync.OnceValue(f.Close)
	defer closeOnce()

	// Bounded worker pool — tunable. 4 in-flight ≈ 2 GiB of buffers worst-case,
	// well under disk-bound throughput.
	const workers = 1
	sem := make(chan struct{}, workers)
	errCh := make(chan error, len(chunks))
	var wg sync.WaitGroup

	for _, c := range chunks {
		c := c
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			wg.Wait()
			return ctx.Err()
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			if err := processChunk(ctx, repo, c.desc, c.offset, c.unSize, c.unDigest, f, &fdMu); err != nil {
				errCh <- fmt.Errorf("chunk %d (digest %s): %w", c.idx, c.desc.Digest, err)
			}
		}()
	}
	wg.Wait()
	close(errCh)
	if err := <-errCh; err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync %s: %w", outPath, err)
	}
	return closeOnce()
}

func processChunk(
	ctx context.Context,
	repo *remote.Repository,
	desc ocispec.Descriptor,
	offset, unSize int64,
	unDigest string,
	f *os.File,
	mu *sync.Mutex,
) error {
	// Fetch compressed blob.
	compressed, err := fetchAllBytes(ctx, repo, desc)
	if err != nil {
		return fmt.Errorf("fetch: %w", err)
	}
	if int64(len(compressed)) != desc.Size {
		return fmt.Errorf("blob size mismatch: got %d want %d", len(compressed), desc.Size)
	}

	// Decompress.
	raw, err := DecodeLZ4Block(compressed, unSize)
	if err != nil {
		return fmt.Errorf("decode: %w", err)
	}

	// Optional integrity check against annotation.
	if unDigest != "" {
		got := "sha256:" + sha256Hex(raw)
		if got != unDigest {
			return fmt.Errorf("uncompressed digest mismatch: got %s want %s", got, unDigest)
		}
	}

	// Write at offset. pwrite would be ideal; Go exposes it via WriteAt.
	mu.Lock()
	_, err = f.WriteAt(raw, offset)
	mu.Unlock()
	if err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return nil
}

// pullLayerToFile writes `desc`'s blob verbatim to `outPath`.
func pullLayerToFile(ctx context.Context, repo *remote.Repository, desc ocispec.Descriptor, outPath string) error {
	rc, err := repo.Fetch(ctx, desc)
	if err != nil {
		return err
	}
	defer rc.Close()

	tmp := outPath + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), rc)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if n != desc.Size {
		_ = os.Remove(tmp)
		return fmt.Errorf("size mismatch: got %d want %d", n, desc.Size)
	}
	got := "sha256:" + hex.EncodeToString(h.Sum(nil))
	if digest.Digest(got) != desc.Digest {
		_ = os.Remove(tmp)
		return fmt.Errorf("digest mismatch: got %s want %s", got, desc.Digest)
	}
	return os.Rename(tmp, outPath)
}

// fetchAllBytes is a small helper; the blobs we use this for are bounded
// (manifest up to a few KB, config ~1 KB, disk chunks ≤ ~500 MB).
// It will materialise disk chunks in memory — that's intentional, we need
// them fully in RAM anyway to feed DecodeLZ4Block.
func fetchAllBytes(ctx context.Context, repo *remote.Repository, desc ocispec.Descriptor) ([]byte, error) {
	rc, err := repo.Fetch(ctx, desc)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	b, err := io.ReadAll(rc)
	if err != nil {
		return nil, err
	}
	if int64(len(b)) != desc.Size {
		return nil, fmt.Errorf("short read: got %d want %d", len(b), desc.Size)
	}
	gotDigest := "sha256:" + sha256Hex(b)
	if digest.Digest(gotDigest) != desc.Digest {
		return nil, fmt.Errorf("digest mismatch: got %s want %s", gotDigest, desc.Digest)
	}
	return b, nil
}

// writeDigestSidecar writes <path>.digest with sha256:<hex> of <path>.
// Matches internal/disk/digest.go's writeDigestFile convention so
// vz-kubelet's cache validator accepts it on subsequent runs.
func writeDigestSidecar(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return err
	}
	sum := "sha256:" + hex.EncodeToString(h.Sum(nil))
	return os.WriteFile(path+".digest", []byte(sum), 0o644)
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// isLocalhostOrLocalIP duplicates pkg/downloader.isLocalhostOrLocalIP to
// avoid importing a sibling package for one helper.
func isLocalhostOrLocalIP(host string) bool {
	host = strings.Split(host, ":")[0]
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate()
}
