## Why it fires

A string or bytes literal is assigned and then passed into a `cryptography`
cipher constructor (e.g. `Cipher(algorithms.AES(key), ...)`). The
taint-style pattern requires the literal to reach the cipher in the same
scope — so it catches hardcoded-secret assignments, not raw key derivations.

## How to fix

Load the key from an environment variable, mounted secret, or KMS call:

```python
import os, base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

key = base64.b64decode(os.environ["DB_KEY_B64"])  # 32-byte AES-256 key
cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
```

## Why this rule defaults off

Experimental + high-noise — the `$KEY = "..."` anchor pattern fires on
test fixtures, TLS demo code, and crypto tutorials. Turn it on once with
`--include-rule cbom-python-hardcoded-key-cipher` on a clean repo, review
the findings, and move confirmed issues to the baseline.
