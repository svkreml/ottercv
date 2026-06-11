package svkreml.certificateViewer.gui.certificateParser;

import lombok.extern.slf4j.Slf4j;

import java.security.*;
import java.security.cert.*;
import java.util.*;

/**
 * PKIX certificate path builder and verifier using BouncyCastle provider.
 * <p>
 * Separates certificates into trust anchors (self-signed roots) and intermediates,
 * then uses {@link CertPathBuilder} to construct and verify a valid X.509 path.
 * CRL revocation checking is delegated to {@link CRLVerifier}.
 *
 * <h3>Usage</h3>
 * <pre>{@code
 * var verifier = new CertificateVerifier(chainCerts);
 * PKIXCertPathBuilderResult result = verifier.verifyCertificate(cert);
 * }</pre>
 */
@Slf4j
public class CertificateVerifier {
    private final Set<TrustAnchor> trustAnchors = new HashSet<>();
    private final CertPathBuilder certPathBuilder;
    private final CertStore certStore;
    private final X509CertSelector selector = new X509CertSelector();

    /**
     * Initializes the verifier by partitioning the given certificates into
     * trust anchors (self-signed) and intermediates.
     *
     * @param additionalCerts certificates to use as trust anchors and intermediates
     * @throws NoSuchAlgorithmException    if PKIX algorithm is unavailable
     * @throws NoSuchProviderException     if BC provider is not registered
     * @throws InvalidAlgorithmParameterException if trust anchors are invalid
     */
    public CertificateVerifier(Set<X509Certificate> additionalCerts) throws
            NoSuchAlgorithmException,
            NoSuchProviderException,
            InvalidAlgorithmParameterException {
        long start = System.currentTimeMillis();
        log.debug("Initializing CertificateVerifier with {} certs", additionalCerts.size());
        Set<X509Certificate> trustedRootCerts = new HashSet<>();
        Set<X509Certificate> intermediateCerts = new HashSet<>();
        for (X509Certificate additionalCert : additionalCerts) {
            boolean selfSigned = isSelfSigned(additionalCert);
            log.debug("Cert subject={}, selfSigned={}", additionalCert.getSubjectX500Principal(), selfSigned);
            if (selfSigned) {
                trustedRootCerts.add(additionalCert);
            } else {
                intermediateCerts.add(additionalCert);
            }
        }
        for (X509Certificate trustedRootCert : trustedRootCerts) {
            trustAnchors.add(new TrustAnchor(trustedRootCert, null));
        }

        certPathBuilder = CertPathBuilder.getInstance("PKIX", "BC");

        certStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(intermediateCerts), "BC");
        long stop = System.currentTimeMillis();
        log.info("CertificateVerifier initialized: {} roots, {} intermediates, {} ms",
                trustedRootCerts.size(), intermediateCerts.size(), (stop - start));
    }

    /**
     * Checks whether a certificate is self-signed by comparing Subject/Issuer DNs
     * and verifying the signature against the certificate's own public key.
     *
     * @param cert certificate to check
     * @return {@code true} if the certificate is self-signed and signature is valid
     */
    public static boolean isSelfSigned(X509Certificate cert) {
        try {
            if (!cert.getIssuerX500Principal().equals(cert.getSubjectX500Principal())) {
                return false;
            }
        } catch (Exception e) {
            log.debug("Error comparing principals for self-signed check: {}", e.getMessage());
            return false;
        }

        try {
            PublicKey key = cert.getPublicKey();
            cert.verify(key);
        } catch (SignatureException | InvalidKeyException e) {
            log.debug("Invalid signature for self-signed check: {}", e.getMessage());
            return false;
        } catch (Exception e) {
            log.debug("Technical error during signature verification for {}: {}",
                    cert.getSubjectX500Principal(), e.getMessage());
        }
        return true;
    }

    private PKIXCertPathBuilderResult verifyCertificateP(X509Certificate cert) throws GeneralSecurityException {
        selector.setCertificate(cert);
        PKIXBuilderParameters pkixParams = new PKIXBuilderParameters(trustAnchors, selector);
        pkixParams.setRevocationEnabled(false);
        List<CertStore> stores = new ArrayList<>();
        stores.add(certStore);

        stores.add(CertStore.getInstance("Collection",
                new CollectionCertStoreParameters(List.of(cert)),
                "BC"));
        pkixParams.setCertStores(stores);
        return (PKIXCertPathBuilderResult) certPathBuilder.build(pkixParams);
    }

    /**
     * Verifies a certificate by building a PKIX cert path and checking CRL revocation.
     *
     * @param cert certificate to verify
     * @return the verified PKIX cert path builder result
     * @throws CertificateVerificationException if CRL check fails
     * @throws GeneralSecurityException if path building fails
     */
    public PKIXCertPathBuilderResult verifyCertificate(X509Certificate cert)
            throws CertificateVerificationException, GeneralSecurityException {

        PKIXCertPathBuilderResult verifiedCertChain =
                verifyCertificateP(cert);
        if (isSelfSigned(cert)) {
            return verifiedCertChain;
        }

        CRLVerifier.verifyCertificateCRLs(cert, verifiedCertChain);

        return verifiedCertChain;
    }

}
