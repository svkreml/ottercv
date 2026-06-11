package svkreml.certificateViewer.gui.certificateParser;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.*;
import svkreml.certificateViewer.gui.view.utils.WebUtils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Certificate Revocation List (CRL) verifier.
 * <p>
 * Downloads CRLs from distribution points specified in certificates,
 * caches them in memory, and checks whether a certificate has been revoked.
 * CRL signatures are verified against the issuer's public key from the cert path.
 *
 * <h3>Caching</h3>
 * Downloaded CRLs are cached per certificate in a thread-safe
 * {@link ConcurrentHashMap}. A cached CRL is re-used until its
 * {@code nextUpdate} time passes.
 */
@Slf4j
@lombok.experimental.UtilityClass
public class CRLVerifier {

    private final Map<X509Certificate, X509CRL> CACHED_CRL = new ConcurrentHashMap<>();

    /**
     * Verifies that the given certificate has not been revoked according to its CRL.
     * <p>
     * The method downloads CRLs from all distribution points listed in the certificate,
     * verifies each CRL's signature, and checks the revocation status.
     *
     * @param cert               certificate to check
     * @param verifiedCertChain  the verified PKIX cert path (used to get the issuer's public key)
     * @throws CertificateVerificationException if no valid CRL is found or the cert is revoked
     */
    public static void verifyCertificateCRLs(X509Certificate cert, PKIXCertPathBuilderResult verifiedCertChain)
            throws CertificateVerificationException {
        try {
            X509CRL crl = CACHED_CRL.get(cert);
            log.debug("CRL check for cert subject={}, cached={}, nextUpdate={}",
                    cert.getSubjectX500Principal(),
                    crl != null,
                    crl != null ? crl.getNextUpdate() : "null");
            if (crl == null || crl.getNextUpdate().toInstant().isBefore(Instant.now())) {
                List<String> crlDistPoints = getCrlDistributionPoints(cert);
                log.debug("CRL distribution points: {}", crlDistPoints);
                for (String crlDP : crlDistPoints) {
                    try {
                        log.info("Downloading CRL: {}", crlDP);
                        try (InputStream crlStream = WebUtils.download(crlDP)) {
                            CertificateFactory cf = CertificateFactory.getInstance("X.509");
                            crl = (X509CRL) cf.generateCRL(crlStream);
                        }
                        log.debug("CRL downloaded, nextUpdate={}, revokedCount={}",
                                crl.getNextUpdate(),
                                crl.getRevokedCertificates() != null ? crl.getRevokedCertificates().size() : 0);
                        List<? extends Certificate> certificates = verifiedCertChain.getCertPath().getCertificates();
                        PublicKey verifierKey = certificates.size() <= 1
                                ? verifiedCertChain.getTrustAnchor().getTrustedCert().getPublicKey()
                                : certificates.getLast().getPublicKey();
                        log.debug("CRL will be verified with key from: {}",
                                certificates.size() <= 1 ? "trust anchor" : "last chain cert");
                        crl.verify(verifierKey, "BC");
                        CACHED_CRL.putIfAbsent(cert, crl);
                        break;
                    } catch (Exception e) {
                        log.error("Failed to download/verify CRL from {}: {}", crlDP, e.getMessage(), e);
                    }
                }
            }
            if (crl == null) {
                throw new CertificateVerificationException(
                        "No valid CRL found for certificate: " + cert.getSubjectX500Principal());
            }
            if (crl.isRevoked(cert)) {
                throw new CertificateVerificationException(
                        "The certificate is revoked by CRL: " + crl);
            }
            log.debug("CRL check passed, cert not revoked");
        } catch (CertificateVerificationException ex) {
            throw ex;
        } catch (Exception ex) {
            log.error("Unexpected error during CRL verification for {}: {}",
                    cert.getSubjectX500Principal(), ex.getMessage(), ex);
            throw new CertificateVerificationException(
                    "Can not verify CRL for certificate: " +
                            cert.getSubjectX500Principal(), ex);
        }
    }

    /**
     * Extracts CRL Distribution Point URLs from a certificate's extensions.
     *
     * @param cert X.509 certificate to inspect
     * @return list of CRL URLs, empty if extension is absent
     * @throws IOException if ASN.1 parsing fails
     */
    public static List<String> getCrlDistributionPoints(
            X509Certificate cert) throws IOException {
        byte[] crldpExt = cert.getExtensionValue(
                Extension.cRLDistributionPoints.getId());
        if (crldpExt == null) {
            return List.of();
        }
        try (ASN1InputStream oAsnInStream = new ASN1InputStream(
                new ByteArrayInputStream(crldpExt))) {
            ASN1Primitive derObjCrlDP = oAsnInStream.readObject();
            DEROctetString dosCrlDP = (DEROctetString) derObjCrlDP;
            byte[] crldpExtOctets = dosCrlDP.getOctets();
            try (ASN1InputStream oAsnInStream2 = new ASN1InputStream(
                    new ByteArrayInputStream(crldpExtOctets))) {
                ASN1Primitive derObj2 = oAsnInStream2.readObject();
                CRLDistPoint distPoint = CRLDistPoint.getInstance(derObj2);
                List<String> crlUrls = new ArrayList<>();
                for (DistributionPoint dp : distPoint.getDistributionPoints()) {
                    DistributionPointName dpn = dp.getDistributionPoint();
                    if (dpn != null && dpn.getType() == DistributionPointName.FULL_NAME) {
                        GeneralName[] genNames = GeneralNames.getInstance(
                                dpn.getName()).getNames();
                        for (GeneralName genName : genNames) {
                            if (genName.getTagNo() == GeneralName.uniformResourceIdentifier) {
                                String url = DERIA5String.getInstance(
                                        genName.getName()).getString();
                                crlUrls.add(url);
                            }
                        }
                    }
                }
                return crlUrls;
            }
        }
    }

}
