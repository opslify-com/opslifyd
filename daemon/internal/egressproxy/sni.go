package egressproxy

import (
	"errors"
	"strings"
)

// errNoSNI means the buffered bytes were not a TLS ClientHello carrying an SNI.
var errNoSNI = errors.New("egressproxy: no SNI in client hello")

// sniFromClientHello parses the server_name (SNI) out of a TLS ClientHello record
// WITHOUT completing (or even beginning) a handshake — the bytes are only read,
// never decrypted. This is what lets pass-through validate SNI against the
// allowlist while still TUNNELING the connection un-decrypted: we look at the
// cleartext ClientHello (SNI is always cleartext in TLS 1.2/1.3 without ECH),
// confirm it, then splice raw bytes upstream. The parser is bounds-checked and
// fail-closed: any malformed field returns errNoSNI rather than panicking.
func sniFromClientHello(b []byte) (string, error) {
	// TLS record header: type(1)=22 handshake, version(2), length(2).
	if len(b) < 5 || b[0] != 0x16 {
		return "", errNoSNI
	}
	rec := int(b[3])<<8 | int(b[4])
	hs := b[5:]
	if len(hs) < rec {
		return "", errNoSNI
	}
	hs = hs[:rec]
	// Handshake header: type(1)=1 client_hello, length(3).
	if len(hs) < 4 || hs[0] != 0x01 {
		return "", errNoSNI
	}
	body := hs[4:]
	// client_version(2) + random(32).
	if len(body) < 34 {
		return "", errNoSNI
	}
	body = body[34:]
	// session_id.
	if len(body) < 1 {
		return "", errNoSNI
	}
	sidLen := int(body[0])
	body = body[1:]
	if len(body) < sidLen {
		return "", errNoSNI
	}
	body = body[sidLen:]
	// cipher_suites.
	if len(body) < 2 {
		return "", errNoSNI
	}
	csLen := int(body[0])<<8 | int(body[1])
	body = body[2:]
	if len(body) < csLen {
		return "", errNoSNI
	}
	body = body[csLen:]
	// compression_methods.
	if len(body) < 1 {
		return "", errNoSNI
	}
	cmLen := int(body[0])
	body = body[1:]
	if len(body) < cmLen {
		return "", errNoSNI
	}
	body = body[cmLen:]
	// extensions.
	if len(body) < 2 {
		return "", errNoSNI
	}
	extLen := int(body[0])<<8 | int(body[1])
	body = body[2:]
	if len(body) < extLen {
		return "", errNoSNI
	}
	body = body[:extLen]
	for len(body) >= 4 {
		extType := int(body[0])<<8 | int(body[1])
		l := int(body[2])<<8 | int(body[3])
		body = body[4:]
		if len(body) < l {
			return "", errNoSNI
		}
		data := body[:l]
		body = body[l:]
		if extType != 0x0000 { // server_name
			continue
		}
		// server_name_list: list_len(2), then entries name_type(1)+name_len(2)+name.
		if len(data) < 2 {
			return "", errNoSNI
		}
		listLen := int(data[0])<<8 | int(data[1])
		data = data[2:]
		if len(data) < listLen {
			return "", errNoSNI
		}
		data = data[:listLen]
		for len(data) >= 3 {
			nameType := data[0]
			nameLen := int(data[1])<<8 | int(data[2])
			data = data[3:]
			if len(data) < nameLen {
				return "", errNoSNI
			}
			name := string(data[:nameLen])
			data = data[nameLen:]
			if nameType == 0 { // host_name
				return strings.ToLower(name), nil
			}
		}
	}
	return "", errNoSNI
}
