package keystore

import (
	"crypto/x509"
	"encoding/binary"
)

// JKS and JCEKS share a binary layout that differs only in the magic number and
// in JCEKS's extra secret-key entry type. Certificate entries (trusted certs and
// the cert chains of private-key entries) are stored as plaintext DER in both
// formats, so they can be enumerated without a password — only the private-key
// blobs and JCEKS secret keys are encrypted.
//
// The existing JKS path uses keystore-go (which also verifies integrity with a
// password). This reader exists for JCEKS, which keystore-go rejects on its
// magic number, and enumerates its certificates directly.
const (
	magicJKS   = 0xFEEDFEED
	magicJCEKS = 0xCECECECE
)

// ksReader is a bounds-checked big-endian cursor over untrusted keystore bytes.
// Every read returns ok=false rather than panicking on a short buffer.
type ksReader struct {
	b   []byte
	pos int
}

func (r *ksReader) u16() (uint16, bool) {
	if r.pos+2 > len(r.b) {
		return 0, false
	}
	v := binary.BigEndian.Uint16(r.b[r.pos:])
	r.pos += 2
	return v, true
}

func (r *ksReader) u32() (uint32, bool) {
	if r.pos+4 > len(r.b) {
		return 0, false
	}
	v := binary.BigEndian.Uint32(r.b[r.pos:])
	r.pos += 4
	return v, true
}

func (r *ksReader) skip(n int) bool {
	if n < 0 || r.pos+n > len(r.b) {
		return false
	}
	r.pos += n
	return true
}

func (r *ksReader) take(n int) ([]byte, bool) {
	if n < 0 || r.pos+n > len(r.b) {
		return nil, false
	}
	v := r.b[r.pos : r.pos+n]
	r.pos += n
	return v, true
}

// utf skips a Java modified-UTF-8 string (2-byte length prefix + bytes).
func (r *ksReader) utf() bool {
	n, ok := r.u16()
	if !ok {
		return false
	}
	return r.skip(int(n))
}

// parseKeystoreCerts enumerates the DER certificates in a JKS/JCEKS stream. It
// stops (returning what it has) on the first entry it cannot safely traverse —
// notably JCEKS secret-key entries, whose serialized form has no length prefix.
// ok reports whether the header was a recognized JKS/JCEKS keystore.
func parseKeystoreCerts(content []byte) (certs []*x509.Certificate, hasPrivateKey, ok bool) {
	r := &ksReader{b: content}
	magic, good := r.u32()
	if !good || (magic != magicJKS && magic != magicJCEKS) {
		return nil, false, false
	}
	version, good := r.u32()
	if !good || (version != 1 && version != 2) {
		return nil, false, false
	}
	count, good := r.u32()
	if !good {
		return nil, false, true
	}

	for i := uint32(0); i < count; i++ {
		tag, good := r.u32()
		if !good {
			break
		}
		if !r.utf() { // alias
			break
		}
		if !r.skip(8) { // creation timestamp
			break
		}
		switch tag {
		case 1: // private-key entry: encrypted key blob + cert chain
			hasPrivateKey = true
			keyLen, good := r.u32()
			if !good || !r.skip(int(keyLen)) {
				return certs, hasPrivateKey, true
			}
			chainLen, good := r.u32()
			if !good {
				return certs, hasPrivateKey, true
			}
			for c := uint32(0); c < chainLen; c++ {
				cert, cont := readKeystoreCert(r, version)
				if !cont {
					return certs, hasPrivateKey, true
				}
				if cert != nil {
					certs = append(certs, cert)
				}
			}
		case 2: // trusted-certificate entry
			cert, cont := readKeystoreCert(r, version)
			if !cont {
				return certs, hasPrivateKey, true
			}
			if cert != nil {
				certs = append(certs, cert)
			}
		default:
			// Tag 3 (JCEKS secret key) or unknown: no length prefix to skip past
			// safely, so stop and return the certs found so far.
			return certs, hasPrivateKey, true
		}
	}
	return certs, hasPrivateKey, true
}

// readKeystoreCert reads one cert record (v2 prefixes it with a UTF cert type).
// cont=false means the buffer was exhausted mid-record; cert may be nil when the
// DER did not parse (recorded as skipped, traversal continues).
func readKeystoreCert(r *ksReader, version uint32) (cert *x509.Certificate, cont bool) {
	if version >= 2 {
		if !r.utf() { // cert type, e.g. "X.509"
			return nil, false
		}
	}
	n, ok := r.u32()
	if !ok {
		return nil, false
	}
	der, ok := r.take(int(n))
	if !ok {
		return nil, false
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, true // unparseable cert entry — skip, keep going
	}
	return parsed, true
}

// openJCEKS enumerates the certificates in a JCEKS keystore. opened reports
// whether the stream was a recognized keystore structure. No password is needed
// because JCEKS certificate entries are stored in the clear.
func openJCEKS(content []byte) (certs []*x509.Certificate, hasPrivateKey, opened bool) {
	return parseKeystoreCerts(content)
}
