package svkreml.certificateViewer.gui.certificateParser;

import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;

import svkreml.certificateViewer.gui.certificateParser.CertificateVerifier;

import static org.assertj.core.api.Assertions.assertThat;

class GuiFlowTest {

    @Test
    void testGuiFlowForSelfSignedCert() throws Exception {
        TestCertUtils.ensureBcProvider();

        X509Certificate cert = TestCertUtils.loadCertFromResources("2F0CB09BE3550EF17EC4F29C90ABD18BFCAAD63A.cer");

        assertThat(cert.getSubjectX500Principal()).isEqualTo(cert.getIssuerX500Principal());

        boolean selfSigned = CertificateVerifier.isSelfSigned(cert);
        assertThat(selfSigned).isTrue();
    }
}
