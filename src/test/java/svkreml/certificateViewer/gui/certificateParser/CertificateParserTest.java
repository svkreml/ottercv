package svkreml.certificateViewer.gui.certificateParser;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class CertificateParserTest {

    @BeforeAll
    static void setup() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    void x500NameToMapExtractsAllRDNs() {
        X500Name name = new X500Name("CN=Test User, O=Test Org, C=RU");
        Map<ASN1ObjectIdentifier, String> map = CertificateParser.x500NameToMap(name);

        assertThat(map).isNotEmpty();
        assertThat(map.values()).contains("Test User", "Test Org", "RU");
    }

    @Test
    void x500NameToMapIteratesRDNsFromLastToFirst() {
        X500Name name = new X500Name("CN=First, OU=Second, O=Third");
        Map<ASN1ObjectIdentifier, String> map = CertificateParser.x500NameToMap(name);

        assertThat(map).hasSize(3);
        assertThat(map.values().iterator().next()).isEqualTo("Third");
    }

    @Test
    void x500NameToMapHandlesRussianAttributes() {
        X500Name name = new X500Name("CN=Тест, O=Организация, C=RU");
        Map<ASN1ObjectIdentifier, String> map = CertificateParser.x500NameToMap(name);

        assertThat(map.values()).contains("Тест", "Организация", "RU");
    }

    @Test
    void getThumbprintSha1Returns40CharHex() throws Exception {
        byte[] certBytes = TestCertUtils.loadCertFromResources("2F0CB09BE3550EF17EC4F29C90ABD18BFCAAD63A.cer").getEncoded();
        String sha1 = CertificateParser.getThumbprintSha1(certBytes);

        assertThat(sha1).hasSize(40);
        assertThat(sha1).matches("[0-9a-f]{40}");
    }

    @Test
    void getThumbprintSha256Returns64CharHex() throws Exception {
        byte[] certBytes = TestCertUtils.loadCertFromResources("2F0CB09BE3550EF17EC4F29C90ABD18BFCAAD63A.cer").getEncoded();
        String sha256 = CertificateParser.getThumbprintSha256(certBytes);

        assertThat(sha256).hasSize(64);
        assertThat(sha256).matches("[0-9a-f]{64}");
    }

    @Test
    void thumbprintsAreConsistent() throws Exception {
        byte[] certBytes = TestCertUtils.loadCertFromResources("2F0CB09BE3550EF17EC4F29C90ABD18BFCAAD63A.cer").getEncoded();

        assertThat(CertificateParser.getThumbprintSha1(certBytes))
                .isEqualTo(CertificateParser.getThumbprintSha1(certBytes));
        assertThat(CertificateParser.getThumbprintSha256(certBytes))
                .isEqualTo(CertificateParser.getThumbprintSha256(certBytes));
    }

    @Test
    void thumbprintsDifferBetweenCerts() throws Exception {
        byte[] cert1 = TestCertUtils.loadCertFromResources("2F0CB09BE3550EF17EC4F29C90ABD18BFCAAD63A.cer").getEncoded();
        byte[] cert2 = TestCertUtils.loadCertFromResources("12BC42082D3F6027A29B7A87FE09B0329631C076.cer").getEncoded();

        assertThat(CertificateParser.getThumbprintSha1(cert1))
                .isNotEqualTo(CertificateParser.getThumbprintSha1(cert2));
    }

    @Test
    void parseX500ToTextAreaFormatsCorrectly() {
        X500Name name = new X500Name("CN=Test, O=Org");
        String result = CertificateParser.parseX500ToTextArea(CertificateParser.x500NameToMap(name));

        assertThat(result).contains("CN = Test");
        assertThat(result).contains("O = Org");
        assertThat(result).doesNotContain("\n\n");
    }

    @Test
    void parseX500ToTextAreaSingleRDN() {
        X500Name name = new X500Name("CN=Only CN");
        String result = CertificateParser.parseX500ToTextArea(CertificateParser.x500NameToMap(name));

        assertThat(result).isEqualTo("CN = Only CN");
    }
}
