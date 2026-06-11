package svkreml.certificateViewer.gui.view.utils;

import lombok.experimental.UtilityClass;

import java.util.Base64;

@UtilityClass
public class Utils {
    private final char PEM_HEADER_MARKER = '-';
    private final char BASE64_FIRST_CHAR = 'M';

    /**
     * Strips PEM headers and decodes Base64-encoded certificate bytes.
     * Handles three formats: PEM with markers, raw Base64, and raw DER.
     *
     * @param certificateBytes raw certificate bytes
     * @return decoded DER certificate bytes
     * @throws IllegalArgumentException if bytes are null or empty
     */
    public static byte[] clearCertBytes(byte[] certificateBytes) {
        if (certificateBytes == null || certificateBytes.length == 0) {
            throw new IllegalArgumentException("Certificate bytes cannot be null or empty");
        }
        if (certificateBytes.length >= 2
                && certificateBytes[0] == PEM_HEADER_MARKER && certificateBytes[1] == PEM_HEADER_MARKER) {
            certificateBytes = new String(certificateBytes).trim()
                    .replace("-----BEGIN CERTIFICATE-----", "")
                    .replace("-----END CERTIFICATE-----", "").getBytes();
            certificateBytes = Base64.getMimeDecoder().decode(certificateBytes);
        } else if (certificateBytes[0] == BASE64_FIRST_CHAR) {
            certificateBytes = Base64.getMimeDecoder().decode(certificateBytes);
        }
        return certificateBytes;
    }
}
