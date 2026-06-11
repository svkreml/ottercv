package svkreml.certificateViewer.gui.certificateParser;

import lombok.experimental.UtilityClass;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.util.encoders.Hex;

import java.security.MessageDigest;
import java.security.cert.X509Certificate;

/**
 * Utility methods for X.509 certificate inspection.
 * <p>
 * Provides helpers for extracting key identifiers (SKI/AKI),
 * computing fingerprints, and detecting self-signed certificates.
 * All methods are null-safe and return {@code null} on parse failure.
 */
@UtilityClass
public class CertUtils {

    /**
     * Extracts the Subject Key Identifier (SKI) from a certificate's extensions.
     *
     * @param certificate X.509 certificate to inspect
     * @return 20-byte key identifier, or {@code null} if extension is absent or malformed
     */
    public static byte[] getSubjectKeyIdentifier(X509Certificate certificate) {
        try {
            byte[] value = certificate.getExtensionValue(Extension.subjectKeyIdentifier.getId());
            return SubjectKeyIdentifier.getInstance(
                    org.bouncycastle.asn1.ASN1OctetString.getInstance(value).getOctets()
            ).getKeyIdentifier();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Extracts the Authority Key Identifier (AKI) from a certificate's extensions.
     *
     * @param certificate X.509 certificate to inspect
     * @return key identifier bytes, or {@code null} if extension is absent or malformed
     */
    public static byte[] getAuthKeyIdentifier(X509Certificate certificate) {
        try {
            byte[] value = certificate.getExtensionValue("2.5.29.35");
            return AuthorityKeyIdentifier.getInstance(
                    org.bouncycastle.asn1.ASN1OctetString.getInstance(value).getOctets()
            ).getKeyIdentifier();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Computes the SHA-256 fingerprint of the DER-encoded certificate.
     *
     * @param cert X.509 certificate
     * @return lowercase hex string of the digest (64 characters), or
     *         {@code "unknown-<hashcode>"} on error
     */
    public static String certFingerprint(X509Certificate cert) {
        try {
            return Hex.toHexString(MessageDigest.getInstance("SHA-256").digest(cert.getEncoded()));
        } catch (Exception e) {
            return "unknown-" + System.identityHashCode(cert);
        }
    }

    /**
     * Checks whether a certificate is self-signed by comparing Subject and Issuer DNs.
     * <p>
     * This is a fast heuristic — it does not verify the cryptographic signature.
     *
     * @param cert X.509 certificate to check
     * @return {@code true} if Subject equals Issuer
     */
    public static boolean isSelfSigned(X509Certificate cert) {
        return cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal());
    }
}
