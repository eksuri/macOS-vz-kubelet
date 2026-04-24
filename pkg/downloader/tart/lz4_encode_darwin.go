//go:build darwin

package tart

/*
#cgo darwin LDFLAGS: -lcompression
#include <compression.h>
#include <stdlib.h>

size_t tart_lz4_encode(
    const unsigned char *src, size_t src_len,
    unsigned char *dst, size_t dst_cap
) {
    return compression_encode_buffer(
        dst, dst_cap,
        src, src_len,
        NULL,
        COMPRESSION_LZ4);
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// EncodeLZ4Block compresses src using Apple's libcompression COMPRESSION_LZ4.
// Exists for symmetry with DecodeLZ4Block and to back round-trip tests; not
// used by the puller (Tart publishes images, we only consume).
func EncodeLZ4Block(src []byte) ([]byte, error) {
	if len(src) == 0 {
		return nil, nil
	}
	cap := len(src) + 64 + len(src)/16
	if cap < 128 {
		cap = 128
	}
	dst := make([]byte, cap)
	n := C.tart_lz4_encode(
		(*C.uchar)(unsafe.Pointer(&src[0])), C.size_t(len(src)),
		(*C.uchar)(unsafe.Pointer(&dst[0])), C.size_t(cap),
	)
	if n == 0 {
		return nil, fmt.Errorf("Apple libcompression LZ4 encode failed (src=%d bytes)", len(src))
	}
	return dst[:n], nil
}
