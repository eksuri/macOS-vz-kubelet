// LZ4 decompression via Apple's Compression framework streaming API.
//
// Tart compresses disk chunks using NSData.compressed(using: .lz4) which
// produces Apple's proprietary stream format (bv41/bv4-/bv4$ framing),
// NOT raw LZ4 blocks. We must use the streaming compression_stream API
// to decode these, not the one-shot compression_decode_buffer.

package tart

/*
#cgo darwin LDFLAGS: -lcompression
#include <compression.h>
#include <stdlib.h>
#include <string.h>

// Streaming decode of an Apple Compression framework LZ4 stream.
// Returns the number of bytes written to dst, or -1 on error.
// dst must be pre-allocated to the expected uncompressed size.
long tart_lz4_stream_decode(
    const unsigned char *src, size_t src_len,
    unsigned char *dst, size_t dst_cap
) {
    compression_stream stream;
    compression_status status;

    status = compression_stream_init(&stream, COMPRESSION_STREAM_DECODE, COMPRESSION_LZ4);
    if (status != COMPRESSION_STATUS_OK) {
        return -1;
    }

    stream.src_ptr = src;
    stream.src_size = src_len;
    stream.dst_ptr = dst;
    stream.dst_size = dst_cap;

    long total_out = 0;
    int flags = 0;

    while (1) {
        // Signal end of input when we've consumed everything
        if (stream.src_size == 0) {
            flags = COMPRESSION_STREAM_FINALIZE;
        }

        status = compression_stream_process(&stream, flags);

        size_t produced = dst_cap - (size_t)(stream.dst_ptr - dst) - stream.dst_size;
        // Actually, track via dst_ptr movement
        // total_out is simply dst_ptr - dst at the end

        if (status == COMPRESSION_STATUS_OK) {
            // More input needed or more output space needed
            if (stream.src_size == 0 && stream.dst_size > 0) {
                // No more input but stream wants more — finalize
                flags = COMPRESSION_STREAM_FINALIZE;
                continue;
            }
            continue;
        } else if (status == COMPRESSION_STATUS_END) {
            break;
        } else {
            // COMPRESSION_STATUS_ERROR
            compression_stream_destroy(&stream);
            return -1;
        }
    }

    total_out = (long)(stream.dst_ptr - dst);
    compression_stream_destroy(&stream);
    return total_out;
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// DecodeLZ4Block decompresses a Tart disk.v2 layer blob using Apple's
// streaming Compression framework API. Tart uses NSData.compressed(using: .lz4)
// which produces Apple's proprietary stream format with bv41 framing — this
// CANNOT be decoded with the one-shot compression_decode_buffer.
func DecodeLZ4Block(compressed []byte, uncompressedSize int64) ([]byte, error) {
	if uncompressedSize <= 0 {
		return nil, fmt.Errorf("invalid uncompressed size %d", uncompressedSize)
	}
	if len(compressed) == 0 {
		return nil, fmt.Errorf("empty compressed input")
	}
	dst := make([]byte, uncompressedSize)

	n := C.tart_lz4_stream_decode(
		(*C.uchar)(unsafe.Pointer(&compressed[0])),
		C.size_t(len(compressed)),
		(*C.uchar)(unsafe.Pointer(&dst[0])),
		C.size_t(uncompressedSize),
	)
	if n < 0 {
		return nil, fmt.Errorf("Apple Compression stream decode failed (compressed=%d bytes, expected=%d bytes)",
			len(compressed), uncompressedSize)
	}
	if int64(n) != uncompressedSize {
		return nil, fmt.Errorf("decoded size mismatch: got %d, expected %d", int64(n), uncompressedSize)
	}
	return dst, nil
}
