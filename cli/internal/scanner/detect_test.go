package scanner

import "testing"

func TestDetectLanguage_NSSAndKeychain(t *testing.T) {
	cases := map[string]string{
		"a/b/x.jks":         ".jks",
		"store.p12":         ".p12",
		"nested/cert9.db":   ".nssdb", // NSS DB -> synthetic ext (routes to keystore)
		"CERT9.DB":          ".nssdb", // case-insensitive
		"key4.db":           ".nssdb",
		"data/app.db":       ".db", // unrelated SQLite -> plain .db (not routed)
		"login.keychain":    ".keychain",
		"login.keychain-db": ".keychain-db",
	}
	for path, want := range cases {
		if got := DetectLanguage(path); got != want {
			t.Errorf("DetectLanguage(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestIsNSSKeystoreFile(t *testing.T) {
	yes := []string{"cert9.db", "path/to/cert8.db", "key3.db", "key4.db", "secmod.db", "KEY4.DB"}
	for _, p := range yes {
		if !IsNSSKeystoreFile(p) {
			t.Errorf("IsNSSKeystoreFile(%q) = false, want true", p)
		}
	}
	no := []string{"app.db", "cert9.sqlite", "cert.db", "cert99.db", "x.jks"}
	for _, p := range no {
		if IsNSSKeystoreFile(p) {
			t.Errorf("IsNSSKeystoreFile(%q) = true, want false", p)
		}
	}
}
