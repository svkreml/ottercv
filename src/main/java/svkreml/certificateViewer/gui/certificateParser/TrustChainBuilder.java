package svkreml.certificateViewer.gui.certificateParser;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.X509CertificateHolder;
import svkreml.certificateViewer.gui.localization.ru.Localization;

import java.security.cert.X509Certificate;
import java.util.Set;

@Slf4j
public class TrustChainBuilder {

    private static final CertificateChainValidator validator = new CertificateChainValidator();

    public static Set<X509Certificate> smallInit(Localization localization, X509CertificateHolder x509CertificateHolder)
            throws Exception {
        return smallInit(localization, KeyParser.loadCertificate(x509CertificateHolder.getEncoded()));
    }

    public static Set<X509Certificate> smallInit(Localization localization, X509Certificate x509Certificate) {
        return validator.buildChain(localization, x509Certificate);
    }

    public static boolean isFromCaFolder(X509Certificate cert) {
        return validator.isFromCaFolder(cert);
    }

    public static Set<X509Certificate> gostTlsStore(Localization localization) {
        return validator.downloadTsl(localization);
    }

    public static byte[] getSubjectKeyIdentifier(X509Certificate cert) {
        return CertUtils.getSubjectKeyIdentifier(cert);
    }
}
