package svkreml.certificateViewer.gui.certificateParser;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.X509CertificateHolder;
import svkreml.certificateViewer.gui.localization.ru.Localization;

import java.security.cert.X509Certificate;
import java.util.Set;

/**
 * Thin facade delegating to {@link CertificateChainValidator}.
 * <p>
 * Provides the legacy static API used by the rest of the application:
 * <ul>
 *   <li>{@link #smallInit} — build a certificate chain</li>
 *   <li>{@link #isFromCaFolder} — check if a cert is from the local CA folder</li>
 *   <li>{@link #gostTlsStore} — download the TSL</li>
 *   <li>{@link #getSubjectKeyIdentifier} — extract SKI from a cert</li>
 * </ul>
 */
@Slf4j
public class TrustChainBuilder {

    private static final CertificateChainValidator validator = new CertificateChainValidator();

    /**
     * Builds a trust chain for the given certificate holder.
     *
     * @param localization application localization
     * @param x509CertificateHolder certificate to build chain for
     * @return chain certificates (excluding the leaf), or empty set
     * @throws Exception on parse or keystore errors
     */
    public static Set<X509Certificate> smallInit(Localization localization, X509CertificateHolder x509CertificateHolder)
            throws Exception {
        return smallInit(localization, KeyParser.loadCertificate(x509CertificateHolder.getEncoded()));
    }

    /**
     * Builds a trust chain for the given certificate.
     *
     * @param localization application localization
     * @param x509Certificate certificate to build chain for
     * @return chain certificates (excluding the leaf), or empty set
     */
    public static Set<X509Certificate> smallInit(Localization localization, X509Certificate x509Certificate) {
        return validator.buildChain(localization, x509Certificate);
    }

    /**
     * Checks whether the given certificate was loaded from the local CA folder.
     *
     * @param cert certificate to check
     * @return {@code true} if the cert is in the CA folder
     */
    public static boolean isFromCaFolder(X509Certificate cert) {
        return validator.isFromCaFolder(cert);
    }

    /**
     * Downloads the TSL and returns all unexpired certificates.
     *
     * @param localization application localization
     * @return set of TSL certificates
     */
    public static Set<X509Certificate> gostTlsStore(Localization localization) {
        return validator.downloadTsl(localization);
    }

    /**
     * Extracts the Subject Key Identifier (SKI) from a certificate.
     *
     * @param cert certificate to inspect
     * @return SKI bytes, or {@code null} if extension is absent
     */
    public static byte[] getSubjectKeyIdentifier(X509Certificate cert) {
        return CertUtils.getSubjectKeyIdentifier(cert);
    }
}
