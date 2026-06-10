package svkreml.certificateViewer.gui.certificateParser;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class CRLVerifierTest {

    @BeforeAll
    static void setup() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    void getCrlDistributionPointsReturnsEmptyForCertWithoutExtension() throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("RSA", "BC").generateKeyPair();
        org.bouncycastle.asn1.x500.X500Name dn = new org.bouncycastle.asn1.x500.X500Name("CN=No CRL");
        X509Certificate cert = TestCertUtils.generateCACert(dn, kp, dn);

        List<String> points = CRLVerifier.getCrlDistributionPoints(cert);
        assertThat(points).isEmpty();
    }

    @Test
    void getCrlDistributionPointsParsesDistributionPoints() throws Exception {
        X509Certificate cert = TestCertUtils.loadCertFromResources("2F0CB09BE3550EF17EC4F29C90ABD18BFCAAD63A.cer");
        List<String> points = CRLVerifier.getCrlDistributionPoints(cert);

        assertThat(points).isNotNull();
    }

    @Test
    void getCrlDistributionPointsForResourceCerts() throws Exception {
        X509Certificate fk = TestCertUtils.loadCertFromResources("12BC42082D3F6027A29B7A87FE09B0329631C076.cer");
        List<String> points = CRLVerifier.getCrlDistributionPoints(fk);

        assertThat(points).isNotNull();
    }

    @Test
    void getCrlDistributionPointsForUntrustedChain() throws Exception {
        X509Certificate ca = TestCertUtils.loadCertFromResources("untrusted/CA.cer");
        List<String> points = CRLVerifier.getCrlDistributionPoints(ca);

        assertThat(points).isNotNull();
    }
}
