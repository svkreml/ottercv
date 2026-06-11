package svkreml.certificateViewer.gui.certificateParser;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;

class KeyParserTest {

    @BeforeAll
    static void setup() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    void keyInfoBuilderCreatesRsaKeyInfo() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(2048);
        X509Certificate cert = generateSelfSignedCert(keyGen.generateKeyPair());

        KeyInfo keyInfo = KeyParser.getKeyInfo(cert.getPublicKey());

        assertThat(keyInfo.getAlgorithm()).isEqualTo("RSA");
        assertThat(keyInfo.getSize()).isEqualTo(2048);
        assertThat(keyInfo.getExponent()).isNotNull();
        assertThat(keyInfo.getDetailedAlgorithm()).contains("rsa");
    }

    @Test
    void keyInfoBuilderCreatesDsaKeyInfo() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "BC");
        keyGen.initialize(1024);
        X509Certificate cert = generateSelfSignedCert(keyGen.generateKeyPair());

        KeyInfo keyInfo = KeyParser.getKeyInfo(cert.getPublicKey());

        assertThat(keyInfo.getAlgorithm()).isEqualTo("DSA");
        assertThat(keyInfo.getSize()).isGreaterThan(0);
        assertThat(keyInfo.getDetailedAlgorithm()).contains("DSA");
    }

    @Test
    void keyInfoBuilderCreatesEcKeyInfo() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "BC");
        keyGen.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = keyGen.generateKeyPair();
        X509Certificate cert = generateSelfSignedCert(kp);

        KeyInfo keyInfo = KeyParser.getKeyInfo(cert.getPublicKey());

        assertThat(keyInfo.getAlgorithm()).isEqualTo("EC");
    }

    @Test
    void loadCertificateParsesDerBytes() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(2048);
        X509Certificate cert = generateSelfSignedCert(keyGen.generateKeyPair());

        X509Certificate parsed = KeyParser.loadCertificate(cert.getEncoded());
        assertThat(parsed).isNotNull();
        assertThat(parsed.getSubjectX500Principal()).isEqualTo(cert.getSubjectX500Principal());
    }

    private static X509Certificate generateSelfSignedCert(KeyPair kp) throws Exception {
        X500Name dn = new X500Name("CN=KeyParser Test Cert");
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                dn, BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + 3600000), dn, kp.getPublic());
        String signerAlg = kp.getPublic().getAlgorithm().equals("EC") ? "SHA256withECDSA"
                : kp.getPublic().getAlgorithm().equals("DSA") ? "SHA256withDSA"
                : "SHA256WithRSA";
        var signer = new JcaContentSignerBuilder(signerAlg).setProvider("BC").build(kp.getPrivate());
        return TestCertUtils.convertToX509Cert(builder.build(signer));
    }
}
