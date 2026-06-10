package svkreml.certificateViewer.gui.certificateParser;

import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.util.encoders.Hex;

import java.security.MessageDigest;
import java.security.cert.X509Certificate;

public final class CertUtils {

    private CertUtils() {
    }

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

    public static byte[] getSubKeyIdentifier(X509Certificate certificate) {
        try {
            byte[] value = certificate.getExtensionValue("2.5.29.14");
            return SubjectKeyIdentifier.getInstance(
                    org.bouncycastle.asn1.ASN1OctetString.getInstance(value).getOctets()
            ).getKeyIdentifier();
        } catch (Exception e) {
            return null;
        }
    }

    public static String certFingerprint(X509Certificate cert) {
        try {
            return Hex.toHexString(MessageDigest.getInstance("SHA-256").digest(cert.getEncoded()));
        } catch (Exception e) {
            return "unknown-" + System.identityHashCode(cert);
        }
    }

    public static boolean isSelfSigned(X509Certificate cert) {
        return cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal());
    }
}
