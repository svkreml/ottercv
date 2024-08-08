package svkreml.certificateViewer.gui.view.utils;

import java.util.Base64;

public class Utils {
    public static byte[] clearCertBytes(byte[] certificateBytes) {
        if (certificateBytes[0] == '-' && certificateBytes[1] == '-') {
            certificateBytes = new String(certificateBytes).trim().
                    replace("-----BEGIN CERTIFICATE-----", "").
                    replace("-----END CERTIFICATE-----", "").getBytes();
            certificateBytes = Base64.getMimeDecoder().decode(certificateBytes);
        } else if (certificateBytes[0] == 'M') {
            certificateBytes = Base64.getMimeDecoder().decode(certificateBytes);
        }
        return certificateBytes;
    }
}
