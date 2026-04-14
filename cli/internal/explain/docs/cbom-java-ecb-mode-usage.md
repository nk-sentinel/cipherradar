## Why it fires

ECB encrypts identical plaintext blocks to identical ciphertext blocks, so
patterns in the input leak directly into the ciphertext. Any use of `AES/ECB/*`,
`DES/ECB/*`, or `Cipher.getInstance("AES")` (which defaults to ECB on the
SunJCE provider) is flagged.

## How to fix

Switch the `Cipher.getInstance` transformation string to an AEAD mode, or
a CBC mode with an explicit random IV and authentication:

```java
// Authenticated, quantum-relevant hardening is a separate step.
Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
byte[] iv = new byte[12];
SecureRandom.getInstanceStrong().nextBytes(iv);
c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
```

## When to suppress

Legitimate cases are rare (format-preserving encryption over exactly one
block, some legacy-interop tools). Prefer `--disable-rule` in configuration
over baselining per-instance.
