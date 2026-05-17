## Why it fires

`math/rand` (and `math/rand/v2` without an entropy seed) is used to
generate keys, IVs, tokens, or session identifiers. `math/rand` is a
deterministic PRNG seeded from the clock and is trivially predictable.

## How to fix

Use `crypto/rand.Read`:

```go
import crand "crypto/rand"

buf := make([]byte, 32)
if _, err := crand.Read(buf); err != nil {
    return fmt.Errorf("reading entropy: %w", err)
}
```

## When to suppress

Non-security random usage — Monte Carlo sampling, test-fixture shuffling,
load-distribution jitter — is legitimate. Scope the suppression with
`--disable-rule` in the package or config rather than silencing the whole
rule; a single hit in a new handler is the main value of this check.
