package javascript_test

import (
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/javascript"
)

func FuzzJSScan(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("not javascript"))
	f.Add([]byte("const crypto = require('crypto'); crypto.createHash('md5')"))
	f.Add([]byte("import crypto from 'crypto'"))
	f.Add([]byte("const jwt = require('jsonwebtoken'); jwt.sign({}, '', { algorithm: 'none' })"))
	f.Add([]byte("const forge = require('node-forge'); forge.md.md5.create()"))
	f.Add([]byte("crypto.subtle.encrypt({ name: 'AES-GCM' }, key, data)"))
	f.Add([]byte("\x00\x01\x02\x03"))
	f.Add([]byte("crypto.createHash("))
	f.Add([]byte("function foo() { return 42; }"))

	f.Fuzz(func(t *testing.T, data []byte) {
		s := javascript.New()
		// Must not panic on any input
		_, _ = s.ScanFile("test.js", data)
	})
}
