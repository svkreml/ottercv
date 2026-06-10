package svkreml.certificateViewer.gui.certificateParser.chainBuilder;

import lombok.extern.slf4j.Slf4j;

import java.security.*;
import java.security.cert.*;
import java.util.*;

@Slf4j
public class CertificateVerifier {
    Set<X509Certificate> trustedRootCerts = new HashSet<>();
    Set<X509Certificate> intermediateCerts = new HashSet<>();
    Set<TrustAnchor> trustAnchors = new HashSet<>();
    CertPathBuilder certPathBuilder;
    CertStore certStore;
    X509CertSelector selector = new X509CertSelector();

    public CertificateVerifier(Set<X509Certificate> additionalCerts) throws
            NoSuchAlgorithmException,
            NoSuchProviderException,
            InvalidAlgorithmParameterException {
        long start = System.currentTimeMillis();
        log.debug("Initializing CertificateVerifier with {} certs", additionalCerts.size());
        for (X509Certificate additionalCert : additionalCerts) {
            boolean selfSigned = isSelfSigned(additionalCert);
            log.debug("Cert subject={}, selfSigned={}", additionalCert.getSubjectX500Principal(), selfSigned);
            if (selfSigned) {
                trustedRootCerts.add(additionalCert);
            } else {
                intermediateCerts.add(additionalCert);
            }
        }
        // Create the trust anchors (set of root CA certificates)

        for (X509Certificate trustedRootCert : trustedRootCerts) {
            trustAnchors.add(new TrustAnchor(trustedRootCert, null));
        }

        certPathBuilder = CertPathBuilder.getInstance("PKIX", "BC");

        certStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(intermediateCerts), "BC");
        long stop = System.currentTimeMillis();
        log.info("CertificateVerifier initialized: {} roots, {} intermediates, {} ms",
                trustedRootCerts.size(), intermediateCerts.size(), (stop - start));
    }

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

        // кладём сертификат,который будем проверять, зачем-то..., кладём отдельно, чтобы он потом нигде не остался
        stores.add(CertStore.getInstance("Collection",
                new CollectionCertStoreParameters(Collections.singletonList(cert)),
                "BC"));
        pkixParams.setCertStores(stores);
        return (PKIXCertPathBuilderResult) certPathBuilder.build(pkixParams);
    }

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
