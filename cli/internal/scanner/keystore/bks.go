package keystore

import "crypto/x509"

// BKS is a BouncyCastle keystore. Unlike JCEKS, its encrypted entry blobs
// (key/secret/sealed) are all length-prefixed, so the whole store can be
// traversed: certificate entries and the cert chain attached to every entry are
// stored in the clear, and the encrypted material is skipped. No password is
// needed to enumerate certificates. The 20-byte trailing HMAC-SHA1 is ignored
// (integrity/weak-password checking is out of scope for this reader).
//
// Format (verified against the pyjks reference implementation and real
// BC-generated fixtures):
//
//	version int32 (1|2) | salt (int32 len + bytes) | iterationCount int32
//	entries... | HMAC-SHA1 (20 bytes)
//
// Each entry:
//
//	type int8 (0=end, 1=cert, 2=key, 3=secret, 4=sealed)
//	alias utf | timestamp int64 | chainLen int32
//	chainLen × (certType utf + certData: int32 len + DER)
//	type-specific:
//	  cert(1):   certType utf + certData(int32 len + DER)
//	  key(2):    keyType int8 + keyFormat utf + keyAlgorithm utf + keyData(int32 len + bytes)
//	  secret(3): secretData(int32 len + bytes)
//	  sealed(4): sealedData(int32 len + bytes)
const bksChainSanityCap = 1 << 20 // guard against a corrupt chain length

func (r *ksReader) u8() (uint8, bool) {
	if r.pos+1 > len(r.b) {
		return 0, false
	}
	v := r.b[r.pos]
	r.pos++
	return v, true
}

// readData reads a 4-byte big-endian length prefix and returns that many bytes.
func (r *ksReader) readData() ([]byte, bool) {
	n, ok := r.u32()
	if !ok {
		return nil, false
	}
	return r.take(int(n))
}

// skipData skips a 4-byte-length-prefixed blob.
func (r *ksReader) skipData() bool {
	n, ok := r.u32()
	if !ok {
		return false
	}
	return r.skip(int(n))
}

// parseBKSCerts enumerates the DER certificates in a BKS keystore. ok reports
// whether the header looked like a BKS store; certs may be empty for an empty
// store. hasPrivateKey is set when a key entry is present. Traversal stops early
// (returning what it has) on truncated/corrupt input rather than panicking.
func parseBKSCerts(content []byte) (certs []*x509.Certificate, hasPrivateKey, ok bool) {
	r := &ksReader{b: content}
	version, good := r.u32()
	if !good || (version != 1 && version != 2) {
		return nil, false, false
	}
	if _, good = r.readData(); !good { // salt
		return nil, false, false
	}
	if _, good = r.u32(); !good { // iteration count
		return nil, false, false
	}

	// readCertRecord reads a (certType utf + certData) record and appends the
	// parsed cert. cont=false means the buffer was exhausted mid-record.
	readCertRecord := func() (cont bool) {
		if !r.utf() { // cert type, e.g. "X.509"
			return false
		}
		der, okData := r.readData()
		if !okData {
			return false
		}
		if c, err := x509.ParseCertificate(der); err == nil {
			certs = append(certs, c)
		}
		return true
	}

	for {
		typ, good := r.u8()
		if !good || typ == 0 { // end-of-entries sentinel
			break
		}
		if !r.utf() { // alias
			break
		}
		if !r.skip(8) { // timestamp
			break
		}
		chainLen, good := r.u32()
		if !good || chainLen > bksChainSanityCap {
			break
		}
		for i := uint32(0); i < chainLen; i++ {
			if !readCertRecord() {
				return certs, hasPrivateKey, true
			}
		}
		switch typ {
		case 1: // certificate entry
			if !readCertRecord() {
				return certs, hasPrivateKey, true
			}
		case 2: // key entry: keyType(1) + keyFormat utf + keyAlgorithm utf + keyData
			hasPrivateKey = true
			if _, good = r.u8(); !good {
				return certs, hasPrivateKey, true
			}
			if !r.utf() || !r.utf() || !r.skipData() {
				return certs, hasPrivateKey, true
			}
		case 3, 4: // secret / sealed: single length-prefixed blob
			if !r.skipData() {
				return certs, hasPrivateKey, true
			}
		default: // unknown entry type — cannot traverse safely
			return certs, hasPrivateKey, true
		}
	}
	return certs, hasPrivateKey, true
}

// openBKS enumerates the certificates in a BKS keystore. opened reports whether
// the stream parsed as a BKS store structure.
func openBKS(content []byte) (certs []*x509.Certificate, hasPrivateKey, opened bool) {
	return parseBKSCerts(content)
}
