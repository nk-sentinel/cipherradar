## Why it fires

`CipherMode.ECB` is assigned to `Aes.Mode`, `DES.Mode`, or a `SymmetricAlgorithm`
subclass. ECB encrypts identical plaintext blocks to identical ciphertext
and reveals structure in the input.

## How to fix

Use an AEAD mode (`AesGcm` in .NET 5+, `ChaCha20Poly1305` in .NET 6+) or
`CipherMode.CBC` with an authenticated HMAC envelope and a random IV:

```csharp
using var aes = Aes.Create();
aes.Mode = CipherMode.CBC;
aes.Padding = PaddingMode.PKCS7;
aes.Key = key32;
aes.GenerateIV();
```

For new code, strongly prefer `AesGcm`.

## When to suppress

Legacy interop (flat-file formats that encode per-record ECB for random
access). Prefer `--disable-rule` at the config level rather than per-file
baselining so intent is auditable.
