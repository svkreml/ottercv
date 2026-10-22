# OtterCV - Otter Certificate Viewer

JavaFX desktop application for viewing and analyzing X.509 certificates and CRLs with Russian GOST crypto infrastructure support.

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

## Help

The application also has an in-app **Справка** tab with usage, network access, and data storage information.

### Launching

#### AppImage

Download `ottercv-<version>-x86_64.AppImage` from the GitHub Releases page, make it executable, and run it:

```bash
chmod +x ottercv-<version>-x86_64.AppImage
./ottercv-<version>-x86_64.AppImage [path/to/certificate-or-crl]
```

The optional argument accepts a certificate or CRL in PEM, DER, or raw Base64 form. Without an argument, the bundled
`certs/default.pem` is opened.

#### From source

```bash
mvn clean package
mvn dependency:copy-dependencies -DincludeScope=runtime -DoutputDirectory=target/libs
java --module-path target/libs:target/ottercv-<version>.jar \
  --add-modules javafx.controls,javafx.graphics \
  -m svkreml.certificateViewer/svkreml.certificateViewer.gui.APP \
  [path/to/certificate-or-crl]
```

### Internet Access Policy

The application only contacts the network when it needs trust or revocation data:

| Data | Source | When | Stored |
|------|--------|------|--------|
| Trusted Service List (TSL) | `https://e-trust.gosuslugi.ru/CA/DownloadTSL?schemaVersion=0` | First run, or when the local cache is older than 30 days | `~/.ottercv/tsl.bks` |
| CRL | CRL distribution points embedded in the opened certificate (`http`, `https`, `ldap`) | During certificate revocation checking | Memory only, until the CRL's `nextUpdate` |
| Issuer certificate | AIA `CA Issuers` URL embedded in the opened certificate (`http`, `https`, `ldap`) | When the issuer is missing from the TSL and local CA folder | Memory only |

- Only the opened certificate's embedded URLs and the fixed TSL URL are used. The application does not crawl directories
  or contact unrelated hosts.
- HTTPS requests use the JVM's default TLS trust store. Certificate validation is not disabled, and no custom or pinned
  trust store is used.
- LDAP distribution points use plain `ldap://` as provided by the certificate; the application does not upgrade them to
  LDAPS.
- Certificates, CRLs, and other user files are never uploaded. No telemetry or analytics is sent.
- If the network is unavailable, local viewing still works; trust and revocation checks may be reported as untrusted or
  unverified.

### Local Data and Temporary Files

The application does not create a dedicated temporary directory. The only persistent runtime data is stored in
`~/.ottercv`:

```
~/.ottercv/
├── tsl.bks   # downloaded TSL cache; delete this file to force a refresh
└── ca/       # optional local root/intermediate certificates (PEM or DER)
```

CRLs and issuer certificates fetched from the network are kept in memory only. Logs are written to standard output, not
to a log file. The Java/AppImage runtime may use the operating system's temporary directory (for example `/tmp`) for its
own internal files; those files are not application data and are managed by the OS.

Build-time downloads are separate from runtime behavior: Maven fetches dependencies from Maven Central, and the
`linux-appimage` profile downloads `appimagetool` from the AppImageKit GitHub releases.

## Running Tests

```bash
mvn test
```

Tests covering chain building, validation, certificate and CRL parsing, CRL signature verification, and revocation checking.

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
├── InputLoader              # Certificate/CRL loading from PEM, DER, raw Base64
├── CrlParser                # CRL → display model conversion
├── CrlSignatureVerifier     # CRL issuer lookup and signature verification
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
| `crl/root.crl`       | Test root CRL (GOST)                 |
| `crl/intermediate.crl` | Test intermediate CRL (GOST)       |
| `crl/root_ca.pem`    | Test root CA                         |
| `crl/intermediate_ca.pem` | Test intermediate CA            |

## Creating a Release

The POM always contains the next development version (`X.Y.Z-SNAPSHOT`). Releases
are created by the **Release** GitHub Actions workflow:

1. Open **Actions → Release → Run workflow** on the default branch.
2. Optionally set `releaseVersion` and `developmentVersion`. By default the
   workflow releases the POM version without `-SNAPSHOT` and bumps the patch
   version for the next development iteration.

The workflow:

- validates the requested versions;
- runs `mvn release:prepare`, which commits the release version, creates and
  pushes the tag `vX.Y.Z`, then commits the next development version;
- checks out the release tag;
- builds the AppImage and publishes it as a GitHub release.

Manually pushing a `v*` tag remains supported: the same workflow builds and
publishes the AppImage without creating release commits.

## Output

```
target/ottercv-<version>-x86_64.AppImage
```
