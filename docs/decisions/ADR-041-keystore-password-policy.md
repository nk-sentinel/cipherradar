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
- **Known limitation — BKS keystores are presence-only.** There is no pure-Go
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
