package svkreml.certificateViewer.gui.certificateParser;

import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.X509TrustedCertificateBlock;
import svkreml.certificateViewer.gui.view.utils.Utils;

import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Loads X.509 certificates and CRLs from PEM, DER, or raw Base64 input.
 */
public final class InputLoader {

    private InputLoader() {
    }

    /**
     * Parses a single certificate or CRL input.
     *
     * @param input PEM, DER, or raw Base64 encoded data
     * @return loaded certificate or CRL
     * @throws IOException if the input is neither a certificate nor a CRL
     */
    public static LoadedInput load(byte[] input) throws IOException {
        if (input == null || input.length == 0) {
            throw new IOException("Input data cannot be null or empty");
        }
        if (isPem(input)) {
            LoadedInput loaded = parseSinglePemObject(input);
            if (loaded != null) {
                return loaded;
            }
            throw new IOException("No certificate or CRL found in PEM input");
        }

        byte[] der = Utils.clearCertBytes(input);
        try {
            return new LoadedInput(new X509CertificateHolder(der), null);
        } catch (IOException certificateException) {
            try {
                return new LoadedInput(null, new X509CRLHolder(der));
            } catch (IOException crlException) {
                throw new IOException("Input is neither an X.509 certificate nor a CRL", crlException);
            }
        }
    }

    /**
     * Parses all certificates from the given input. Useful for PEM files that
     * contain a certificate chain.
     *
     * @param input PEM or DER encoded certificate data
     * @return parsed certificates
     * @throws IOException if the input contains no certificates
     */
    public static List<X509CertificateHolder> loadCertificates(byte[] input) throws IOException {
        if (input == null || input.length == 0) {
            throw new IOException("Input data cannot be null or empty");
        }
        List<X509CertificateHolder> certificates = new ArrayList<>();
        if (isPem(input)) {
            try (PEMParser parser = new PEMParser(new StringReader(decodeText(input)))) {
                Object object;
                while ((object = parser.readObject()) != null) {
                    X509CertificateHolder certificate = asCertificate(object);
                    if (certificate != null) {
                        certificates.add(certificate);
                    }
                }
            }
        } else {
            certificates.add(new X509CertificateHolder(Utils.clearCertBytes(input)));
        }
        if (certificates.isEmpty()) {
            throw new IOException("No certificates found in input");
        }
        return certificates;
    }

    private static LoadedInput parseSinglePemObject(byte[] input) throws IOException {
        try (PEMParser parser = new PEMParser(new StringReader(decodeText(input)))) {
            Object object;
            while ((object = parser.readObject()) != null) {
                if (object instanceof X509CertificateHolder certificate) {
                    return new LoadedInput(certificate, null);
                }
                if (object instanceof X509CRLHolder crl) {
                    return new LoadedInput(null, crl);
                }
                X509CertificateHolder certificate = asCertificate(object);
                if (certificate != null) {
                    return new LoadedInput(certificate, null);
                }
            }
        }
        return null;
    }

    private static X509CertificateHolder asCertificate(Object object) {
        if (object instanceof X509CertificateHolder certificate) {
            return certificate;
        }
        if (object instanceof X509TrustedCertificateBlock trustedCertificateBlock) {
            return trustedCertificateBlock.getCertificateHolder();
        }
        return null;
    }

    private static boolean isPem(byte[] input) {
        return new String(input, StandardCharsets.UTF_8).contains("-----BEGIN ");
    }

    private static String decodeText(byte[] input) {
        return new String(input, StandardCharsets.UTF_8);
    }

    /**
     * Result of loading an input file.
     */
    public record LoadedInput(X509CertificateHolder certificate, X509CRLHolder crl) {
        public boolean isCertificate() {
            return certificate != null;
        }

        public boolean isCrl() {
            return crl != null;
        }
    }
}
