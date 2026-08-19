package egressproxy

import (
	"bufio"
	"io"
	"net"
)

// newConnReader wraps a conn in a buffered reader suitable for http.ReadRequest.
func newConnReader(c net.Conn) *bufio.Reader {
	return bufio.NewReader(c)
}

// peekResult holds the bytes read to capture a ClientHello (buffered) plus a
// reader for everything that follows (rest), so the caller can replay buffered
// upstream and then splice rest without losing a byte.
type peekResult struct {
	buffered []byte
	rest     io.Reader
}

// maxClientHello bounds how many bytes we buffer looking for the ClientHello, so a
// sandbox cannot make us buffer unboundedly. A ClientHello record is far smaller.
const maxClientHello = 16 << 10 // 16 KiB

// peekClientHello reads one TLS record header + its payload from c (bounded), so
// the SNI can be validated, and returns the buffered bytes plus a reader that
// continues the stream. The connection is NEVER decrypted — only these cleartext
// handshake bytes are inspected.
func peekClientHello(c net.Conn) (peekResult, error) {
	br := bufio.NewReaderSize(c, maxClientHello)
	// Peek the 5-byte record header to learn the record length.
	hdr, err := br.Peek(5)
	if err != nil {
		// Not enough bytes / not TLS: return what we can, let the caller decide.
		buffered, _ := io.ReadAll(io.LimitReader(br, int64(br.Buffered())))
		return peekResult{buffered: buffered, rest: br}, nil
	}
	recLen := int(hdr[3])<<8 | int(hdr[4])
	total := 5 + recLen
	if total > maxClientHello {
		total = maxClientHello
	}
	buffered := make([]byte, total)
	if _, err := io.ReadFull(br, buffered); err != nil {
		return peekResult{}, err
	}
	return peekResult{buffered: buffered, rest: br}, nil
}
