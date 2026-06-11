# OtterCV - Otter Certificate Viewer

JavaFX desktop application for viewing and analyzing X.509 certificates with Russian GOST crypto infrastructure support.

## Requirements

- JDK 21+
- Apache Maven 3.9.0+
- BouncyCastle provider (bundled)

## Building

```bash
# Full build
mvn clean package

# Linux AppImage (standalone)
mvn clean package -P linux-appimage

# Portable Linux AppImage (requires Docker)
./build-appimage-docker.sh
```

## Running Tests

```bash
mvn test
```

52 tests covering chain building, validation, certificate parsing, and CRL verification.

## Architecture

```
certificateParser/
├── CertificateParser        # Main entry point: getCertificateModel(), Validate inner class
├── CertificateChainValidator # Unified chain building + PKIX validation API
├── ChainWalker              # Walks AKI→SKI links in a keystore to build chains
├── CertUtils                # Utility: SKI/AKI extraction, fingerprint, isSelfSigned
├── TslStore                 # TSL download, BKS keystore management, CA folder loading
├── CertificateVerifier      # PKIX cert path builder (BouncyCastle)
├── CRLVerifier              # CRL download, caching, revocation checking
├── TrustChainBuilder        # Thin facade (legacy static API)
├── KeyParser                # Certificate/key loading from bytes
├── ExtensionParser          # X.509 extension → display string conversion
├── CustomBCStyle            # X500Name style with Russian GOST OIDs
├── KeyInfo                  # Key algorithm/size/exponent data class
└── Messages                 # String constants for trust-source messages
```

### Certificate Validation Flow

```
CertificateParser.Validate.invoke()
  ├── CertificateChainValidator.buildChain()
  │     ├── TslStore.loadKeyStore()  →  BKS keystore
  │     └── ChainWalker.buildChain() →  chain via AKI→SKI matching
  ├── CertificateVerifier(chain)     →  PKIX path builder
  └── CRLVerifier.verifyCertificateCRLs()  →  revocation check
```

### Chain Building (ChainWalker)

For each certificate, looks up the issuer in the keystore by matching the AKI (Authority Key Identifier) against SKIs (
Subject Key Identifiers) of stored certificates. When multiple candidates share the same SKI, `pickOne` disambiguates by
preferring self-signed certificates (shortest chain). A visited-set prevents infinite loops on circular references.

### Trust Sources

| Source        | Description                                          |
|---------------|------------------------------------------------------|
| **TSL**       | Trusted Service List (downloaded XML → BKS keystore) |
| **CA_FOLDER** | Local `ca/` directory next to the BKS file           |

## Test Resources

| File                 | Description                          |
|----------------------|--------------------------------------|
| `2F0CB09B...cer`     | Минцифры self-signed root            |
| `12BC4208...cer`     | ФК issued by Минцифры                |
| `1D131217...cer`     | Минцифры cross-cert from Минкомсвязь |
| `untrusted/ROOT.cer` | Test root CA (GOST, not trusted)     |
| `untrusted/CA.cer`   | Test intermediate CA                 |
| `untrusted/USER.cer` | Test end-entity cert                 |

## Creating a Release

```bash
git tag v1.1.1
git push origin v1.1.1
```

## Output

```
target/ottercv-<version>-x86_64.AppImage
```
