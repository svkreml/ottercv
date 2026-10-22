package svkreml.certificateViewer.gui.certificateParser;

import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class InputLoaderTest {

    private static final String ROOT_CRL = "src/test/resources/crl/root.crl";
    private static final String ROOT_CERT = "src/test/resources/crl/root_ca.pem";

    @BeforeAll
    static void setup() {
        TestCertUtils.ensureBcProvider();
    }

    @Test
    void loadsDerCrl() throws Exception {
        byte[] der = read(ROOT_CRL);

        InputLoader.LoadedInput input = InputLoader.load(der);

        assertThat(input.isCrl()).isTrue();
        assertThat(input.isCertificate()).isFalse();
        assertThat(input.crl().getIssuer().toString()).contains("Восход");
    }

    @Test
    void loadsPemCrl() throws Exception {
        byte[] der = read(ROOT_CRL);
        String pem = toPem(new X509CRLHolder(der));

        InputLoader.LoadedInput input = InputLoader.load(pem.getBytes(StandardCharsets.UTF_8));

        assertThat(input.isCrl()).isTrue();
        assertThat(input.crl().getIssuer().toString()).contains("Восход");
    }

    @Test
    void loadsRawBase64Crl() throws Exception {
        byte[] der = read(ROOT_CRL);
        byte[] base64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                .encode(der);

        InputLoader.LoadedInput input = InputLoader.load(base64);

        assertThat(input.isCrl()).isTrue();
        assertThat(input.crl().getIssuer().toString()).contains("Восход");
    }

    @Test
    void loadsPemCertificate() throws Exception {
        byte[] pem = read(ROOT_CERT);

        InputLoader.LoadedInput input = InputLoader.load(pem);

        assertThat(input.isCertificate()).isTrue();
        assertThat(input.certificate().getSubject().toString()).contains("Восход");
    }

    @Test
    void loadsCertificateChain() throws Exception {
        byte[] pem = read(ROOT_CERT);

        List<org.bouncycastle.cert.X509CertificateHolder> certificates =
                InputLoader.loadCertificates(pem);

        assertThat(certificates).hasSize(1);
    }

    @Test
    void rejectsUnknownData() {
        assertThatThrownBy(() -> InputLoader.load("not a certificate".getBytes(StandardCharsets.UTF_8)))
                .isInstanceOf(Exception.class);
    }

    private static byte[] read(String path) throws Exception {
        return Files.readAllBytes(new File(path).toPath());
    }

    private static String toPem(Object object) throws Exception {
        StringWriter stringWriter = new StringWriter();
        try (JcaPEMWriter writer = new JcaPEMWriter(stringWriter)) {
            writer.writeObject(object);
        }
        return stringWriter.toString();
    }
}
