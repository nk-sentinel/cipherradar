## Why it fires

A byte literal or string literal flows directly into `aes.NewCipher` (or a
wrapper). Hardcoded keys embed secrets in the binary, survive grep, and
cannot be rotated without a redeploy.

## How to fix

Load the key from a KMS, environment variable, or a secret-mounted file.
Keys should be 32 bytes (AES-256) and distinct per data-at-rest purpose:

```go
keyB64 := os.Getenv("DB_ENCRYPTION_KEY")
key, _ := base64.StdEncoding.DecodeString(keyB64)
block, _ := aes.NewCipher(key)
```

## When to suppress

Key-schedule tests, crypto-library unit tests that exercise known-answer
vectors, and fuzzing corpora routinely embed literal keys. Suppress these
with `--disable-rule cbom-go-hardcoded-key-aes` scoped to the test file
(via `// cradar:disable-next-line` or baseline).
