# CBOM Signing and Verification

CipherRadar signs every generated CBOM using [Sigstore cosign](https://docs.sigstore.dev/signing/signing_with_blobs/), providing tamper-evident provenance for your Cryptography Bill of Materials.

## How keyless signing works

In keyless mode (the default), CipherRadar uses the Sigstore public-good infrastructure:

1. **Fulcio** issues a short-lived signing certificate tied to an OIDC identity (workload identity in CI, or a developer's SSO identity locally).
2. **cosign sign-blob** signs the CBOM JSON with the ephemeral key and uploads the signature to the **Rekor** transparency log.
3. CipherRadar stores the base64-encoded signature and the Rekor log entry index alongside the CBOM record.

No long-lived private keys are created or stored. The OIDC token is the only authentication material, and the signing certificate expires within minutes.

## Verifying a signed CBOM

Given a CBOM file and its detached signature:

```bash
# Verify against the Sigstore public-good instance
cosign verify-blob \
  --signature cbom.sig \
  --certificate-identity "scanner@cipherradar.example.com" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  cbom.json
```

- `--certificate-identity` must match the OIDC subject that performed the signing (e.g., a GitHub Actions workflow identity or service account email).
- `--certificate-oidc-issuer` must match the issuer URL of the OIDC provider.

You can also look up the entry directly on the Rekor transparency log:

```bash
rekor-cli get --log-index <rekor_log_id>
```

## Air-gapped mode: org-managed keys

For environments without internet access (air-gapped deployments), you can use a traditional key pair instead of keyless signing.

### Generate a key pair

```bash
cosign generate-key-pair
# Produces cosign.key (private, encrypted) and cosign.pub (public)
```

### Sign with a local key

```bash
cosign sign-blob --key cosign.key --output-signature cbom.sig cbom.json
```

### Verify with the public key

```bash
cosign verify-blob --key cosign.pub --signature cbom.sig cbom.json
```

### Helm configuration for key-based signing

```yaml
signing:
  enabled: true
  keylessMode: false
  # Mount the private key as a Kubernetes secret
  privateKeySecret: "cipherradar-cosign-key"
  privateKeySecretKey: "cosign.key"
```

Create the secret:

```bash
kubectl create secret generic cipherradar-cosign-key \
  --from-file=cosign.key=./cosign.key
```

## Configuration for self-hosted Sigstore stack

Organizations running their own Sigstore infrastructure (TUF root, Fulcio CA, Rekor log) should set the following environment variables on the scanner worker:

| Variable | Description | Example |
|---|---|---|
| `COSIGN_REKOR_URL` | Rekor transparency log URL | `https://rekor.internal.example.com` |
| `COSIGN_FULCIO_URL` | Fulcio CA URL | `https://fulcio.internal.example.com` |
| `COSIGN_MIRROR` | TUF mirror URL | `https://tuf.internal.example.com` |
| `COSIGN_ROOT` | Path to custom TUF root.json | `/etc/sigstore/root.json` |
| `SIGSTORE_CT_LOG_PUBLIC_KEY_FILE` | CT log public key for verification | `/etc/sigstore/ctfe.pub` |

### Helm values for self-hosted Sigstore

```yaml
signing:
  enabled: true
  keylessMode: true
  cosignImage: "gcr.io/projectsigstore/cosign:v2"
  rekorUrl: "https://rekor.internal.example.com"
  fulcioUrl: "https://fulcio.internal.example.com"
  tufMirror: "https://tuf.internal.example.com"

scannerWorker:
  env:
    COSIGN_REKOR_URL: "https://rekor.internal.example.com"
    COSIGN_FULCIO_URL: "https://fulcio.internal.example.com"
    COSIGN_MIRROR: "https://tuf.internal.example.com"
```

## Disabling signing

To disable CBOM signing entirely, set:

```yaml
signing:
  enabled: false
```

The scanner worker will skip the signing step, and CBOMs will be stored without a signature.
