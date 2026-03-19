package php_test

import (
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/php"
)

func FuzzPHPScan(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("not php code at all"))
	f.Add([]byte("<?php echo 'hello'; ?>"))
	f.Add([]byte("<?php\n$encrypted = openssl_encrypt($data, 'AES-256-CBC', $key);\n"))
	f.Add([]byte("<?php\nopenssl_decrypt($data, 'DES-ECB', $key);\n"))
	f.Add([]byte("<?php\nhash('sha256', $data);\n"))
	f.Add([]byte("<?php\nhash_hmac('sha256', $data, $key);\n"))
	f.Add([]byte("<?php\nhash_pbkdf2('sha256', $password, $salt, 10000, 32);\n"))
	f.Add([]byte("<?php\npassword_hash($password, PASSWORD_BCRYPT);\n"))
	f.Add([]byte("<?php\nsodium_crypto_secretbox($data, $nonce, $key);\n"))
	f.Add([]byte("<?php\nmcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, $data, MCRYPT_MODE_CBC);\n"))
	f.Add([]byte("<?php\nopenssl_sign($data, $sig, $key, OPENSSL_ALGO_SHA256);\n"))
	f.Add([]byte("<?php\nopenssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA]);\n"))
	f.Add([]byte("\x00\x01\x02\x03"))
	f.Add([]byte("<?php\n$algo = 'sha256';\nhash($algo, $data);\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		s := php.New()
		// Must not panic on any input
		_, _ = s.ScanFile("test.php", data)
	})
}
