# ADR-041: Keystore inspection & default-password policy

**Status:** Accepted (2026-06-21)

## Context

`cradar` inventories certificates. Certificates also live inside binary
keystores — Java KeyStore (JKS) and PKCS#12 (`.p12`/`.pfx`) — which are usually
password-protected. To inventory the certs inside (and flag a real, common
misconfiguration), `cradar` must attempt to open them. Opening requires a
password, which raises a dual-use concern: a scanner that brute-forces
credentials changes the tool's character and risk profile.

## Decision

1. **Always emit a presence finding** for any discovered keystore (path-stamped),
   even when it cannot be opened. A committed keystore is itself inventory.
2. **Enumerate certificates** (and note private-key presence) when the store
   opens. Embedded certs reuse the shared certificate modeling (ADR-040 +
   the cert linked-graph), so they are indistinguishable from file certs.
3. **Try a small, curated set of well-known default/weak passwords**, baked into
   the binary — never downloaded at runtime. The set is researched platform
   defaults (JDK `changeit`, Android `android`, GCP `notasecret`, WebLogic demo
   stores, …) plus a list shared from a prior SonarQube cert-expiry plugin, plus
   the filename and empty string. PKCS#12 enforces a 6-char minimum, so shorter
   entries apply to JKS only.
4. **A store that opens with a default/weak password is a HIGH security finding**
   (`cbom-keystore-weak-password`) in addition to the inventory.
5. **Opt-in extension only.** Users may supply additional candidates via
   `--keystore-wordlist <file>` (offline, user-provided). `cradar` never fetches
   wordlists from the network and ships no large dictionary.

## Rejected alternatives

- **Auto-download a password dictionary and brute-force.** Rejected: trips
  AV/EDR, breaks the offline/air-gapped posture (ADR-003), is slow against the
  iterated KDFs keystores use, is non-deterministic, and offers low marginal
  value — a parsed certificate already reveals its key's algorithm and size.
- **Skip keystores entirely.** Rejected: misses cryptographic material that
  ships with the product and a high-value misconfiguration signal.

## Consequences

- The default-password set is a maintained constant; additions are low-risk.
- **Known limitation — BKS keystores are presence-only.** _(Superseded — see the
  2026-07 addendum below: BKS is now enumerated by a pure-Go reader.)_ There is no pure-Go
  BKS parser (the format is BouncyCastle/Java-specific), so a `.bks` file yields
  a path-stamped presence finding noting "format not parsed" — it is not run
  through the JKS loader and is never misreported as password-locked.
  **Why not via the JDK?** Enumerating BKS would mean shelling out to Java's
  `keytool`, but `keytool` reads JKS/JCEKS/PKCS12 natively and **cannot** read
  BKS without the BouncyCastle provider JAR (`-providerclass
  org.bouncycastle.jce.provider.BouncyCastleProvider -providerpath bcprov.jar`).
  So even a machine with Java installed cannot enumerate BKS unless `bcprov.jar`
  is also provisioned. A `keytool` subprocess path is therefore **deliberately
  not implemented**: it would add a Java runtime dependency (breaking the
  pure-Go / no-runtime default) and BKS would still need a separate BouncyCastle
  JAR. **Workaround:** convert the store out-of-band
  (`keytool -importkeystore -srcstoretype BKS -deststoretype PKCS12`) and scan
  the resulting `.p12`, which cradar reads natively.
- Base64-encoded certificates embedded in Kubernetes Secret data are now
  decoded (`cbom-configfile-k8s-cert`); inline PEM in any text config was
  already covered by the universal regex scanner.

## Addendum (2026-07): pure-Go readers for JCEKS + BKS; presence capture extended

The "BKS keystores are presence-only" limitation above is **resolved** for the
plaintext-cert case. cradar now enumerates certificates from JCEKS and BKS
stores with **pure-Go readers** — no Java runtime, no BouncyCastle JAR:

- **JCEKS** (`.jceks`): keystore-go rejects its magic number, but its certificate
  entries (trusted certs + private-key cert chains) are plaintext DER, so they
  are read directly without a password.
- **BKS** (`.bks`): its store data is plaintext (the encrypted key/secret/sealed
  blobs are length-prefixed and skipped), so the whole store traverses and its
  certs enumerate without a password. Verified against real BouncyCastle-
  generated fixtures.

Both reuse the shared certificate modeling and are fully bounds-checked against
malformed input. The `keytool`/BouncyCastle-JAR subprocess path discussed above
is therefore no longer needed for BKS.

The remaining **encrypted or non-Java formats stay presence-only** (captured,
not enumerated) — their contents can't be read without the store password plus a
format-specific implementation:

- **BCFKS** (`.bcfks`) and **UBER** (`.ubr`/`.uber`): whole-store-encrypted
  BouncyCastle formats — enumeration needs the password + a BouncyCastle
  implementation (a bundled Java/BC helper, tracked separately and deferred).
- **macOS Keychain** (`.keychain`/`.keychain-db`) and **Mozilla NSS** cert/key
  databases (`cert9.db`, `key4.db`, …): different, non-X.509 formats. NSS files
  are matched by exact filename (routed via a synthetic `.nssdb` extension) so
  unrelated `.db` SQLite files are not swept in.

Net: every keystore/cert-store format with a recognizable extension is now at
least **captured** — parsed where the certs are plaintext (JKS, PKCS12, JCEKS,
BKS), presence-only where the store is encrypted or non-Java. Password
harvesting (config keys + keystore-load API arguments; coverage-only, never
reported) additionally unlocks otherwise-locked stores so their certs inventory.
