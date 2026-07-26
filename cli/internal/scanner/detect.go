package scanner

import (
	"path/filepath"
	"strings"
)

// nssKeystoreFiles are the well-known Mozilla NSS certificate/key database
// filenames. NSS stores use the generic `.db` extension, so they are matched by
// exact filename — routing every `.db` file would sweep in unrelated SQLite
// databases.
var nssKeystoreFiles = map[string]bool{
	"cert8.db":  true,
	"cert9.db":  true,
	"key3.db":   true,
	"key4.db":   true,
	"secmod.db": true,
}

// IsNSSKeystoreFile reports whether path is a Mozilla NSS cert/key database.
func IsNSSKeystoreFile(path string) bool {
	return nssKeystoreFiles[strings.ToLower(filepath.Base(path))]
}

// DetectLanguage returns the file extension (lowercased, with dot) for a given file path.
// Returns empty string if the extension is not recognized. NSS cert/key databases
// are matched by filename and mapped to a synthetic ".nssdb" extension so the
// keystore scanner can claim them without also claiming every `.db` file.
func DetectLanguage(path string) string {
	if IsNSSKeystoreFile(path) {
		return ".nssdb"
	}
	ext := strings.ToLower(filepath.Ext(path))
	return ext
}
