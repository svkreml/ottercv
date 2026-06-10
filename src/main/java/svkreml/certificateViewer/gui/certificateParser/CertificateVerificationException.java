package svkreml.certificateViewer.gui.certificateParser;

import java.io.Serial;

/**
 * Exception thrown when certificate or CRL verification fails.
 * <p>
 * Used by {@link CertificateVerifier} and {@link CRLVerifier} to signal
 * validation errors such as missing CRLs, revoked certificates, or
 * unverifiable signatures.
 */
public class CertificateVerificationException extends Exception {
    @Serial private static final long serialVersionUID = 1L;

    public CertificateVerificationException(String message, Throwable cause) {
        super(message, cause);
    }

    public CertificateVerificationException(String message) {
        super(message);
    }
}
