package svkreml.certificateViewer.gui.certificateParser;

import org.bouncycastle.cert.X509CRLHolder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import svkreml.certificateViewer.gui.api.model.CrlStatus;
import svkreml.certificateViewer.gui.localization.ru.Localization;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

class CrlSignatureVerifierTest {

    private static final Path ROOT_CRL = Path.of("src/test/resources/crl/root.crl");
    private static final Path INTERMEDIATE_CRL = Path.of("src/test/resources/crl/intermediate.crl");

    @BeforeAll
    static void setup() {
        TestCertUtils.ensureBcProvider();
    }

    @Test
    void verifiesIntermediateCrlSignatureWithCertificateFromSameDirectory() throws Exception {
        Localization localization = Localization.init();
        X509CRLHolder crl = load(INTERMEDIATE_CRL);

        CrlSignatureVerifier.VerificationResult result =
                CrlSignatureVerifier.verify(crl, INTERMEDIATE_CRL, localization);

        assertThat(result.details()).contains(localization.CRL_SIGNATURE_VALID);
        assertThat(result.details()).anyMatch(line -> line.contains("Выдра УЦ Восход2"));
        assertThat(result.status()).isIn(CrlStatus.VALID, CrlStatus.EXPIRED);
    }

    private static X509CRLHolder load(Path path) throws Exception {
        return new X509CRLHolder(Files.readAllBytes(new File(path.toString()).toPath()));
    }
}
