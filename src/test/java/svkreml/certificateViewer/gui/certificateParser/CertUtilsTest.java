package svkreml.certificateViewer.gui.certificateParser;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;

class CertUtilsTest {

    @BeforeAll
    static void setup() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    void getSubjectKeyIdentifierReturnsNonNull() throws Exception {
        X509Certificate cert = TestCertUtils.loadCertFromResources("2F0CB09BE3550EF17EC4F29C90ABD18BFCAAD63A.cer");
        byte[] ski = CertUtils.getSubjectKeyIdentifier(cert);
        assertThat(ski).isNotNull();
        assertThat(ski.length).isGreaterThan(0);
    }

    @Test
    void getSubjectKeyIdentifierReturnsNullForCertWithoutExtension() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(2048);
        KeyPair kp = keyGen.generateKeyPair();

        org.bouncycastle.asn1.x500.X500Name dn =
                new org.bouncycastle.asn1.x500.X500Name("CN=No Extension Cert");
        org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder builder =
                new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(
                        dn,
                        java.math.BigInteger.ONE,
                        new java.util.Date(),
                        new java.util.Date(System.currentTimeMillis() + 3600000),
                        dn,
                        kp.getPublic());
        org.bouncycastle.operator.ContentSigner signer =
                new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        org.bouncycastle.cert.X509CertificateHolder holder = builder.build(signer);
        X509Certificate cert = TestCertUtils.convertToX509Cert(holder);

        byte[] ski = CertUtils.getSubjectKeyIdentifier(cert);
        assertThat(ski).isNull();
    }

    @Test
    void getAuthKeyIdentifierReturnsNonNullForEndEntity() throws Exception {
        X509Certificate root = TestCertUtils.generateCACert(
                new org.bouncycastle.asn1.x500.X500Name("CN=Root"),
                KeyPairGenerator.getInstance("RSA", "BC").generateKeyPair(),
                new org.bouncycastle.asn1.x500.X500Name("CN=Root"));

        X509Certificate child = TestCertUtils.generateEndEntityCert(
                new org.bouncycastle.asn1.x500.X500Name("CN=Child"),
                KeyPairGenerator.getInstance("RSA", "BC").generateKeyPair(),
                new org.bouncycastle.asn1.x500.X500Name("CN=Root"),
                root.getPublicKey());

        byte[] aki = CertUtils.getAuthKeyIdentifier(child);
        assertThat(aki).isNotNull();
        assertThat(aki.length).isGreaterThan(0);
    }

    @Test
    void getAuthKeyIdentifierReturnsNonNullForSelfSignedCert() throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("RSA", "BC").generateKeyPair();
        X509Certificate root = TestCertUtils.generateCACert(
                new org.bouncycastle.asn1.x500.X500Name("CN=Root"),
                kp,
                new org.bouncycastle.asn1.x500.X500Name("CN=Root"));

        byte[] aki = CertUtils.getAuthKeyIdentifier(root);
        assertThat(aki).isNotNull();
    }

    @Test
    void getSubjectKeyIdentifierReturnsNonNullForResourceCert() throws Exception {
        X509Certificate cert = TestCertUtils.loadCertFromResources("2F0CB09BE3550EF17EC4F29C90ABD18BFCAAD63A.cer");
        byte[] ski = CertUtils.getSubjectKeyIdentifier(cert);
        assertThat(ski).isNotNull();
        assertThat(ski.length).isGreaterThan(0);
    }

    @Test
    void certFingerprintReturnsConsistentSha256() throws Exception {
        X509Certificate cert = TestCertUtils.loadCertFromResources("2F0CB09BE3550EF17EC4F29C90ABD18BFCAAD63A.cer");
        String fp1 = CertUtils.certFingerprint(cert);
        String fp2 = CertUtils.certFingerprint(cert);
        assertThat(fp1).isEqualTo(fp2);
        assertThat(fp1).hasSize(64);
    }

    @Test
    void certFingerprintDiffersBetweenCerts() throws Exception {
        X509Certificate cert1 = TestCertUtils.loadCertFromResources("2F0CB09BE3550EF17EC4F29C90ABD18BFCAAD63A.cer");
        X509Certificate cert2 = TestCertUtils.loadCertFromResources("12BC42082D3F6027A29B7A87FE09B0329631C076.cer");
        assertThat(CertUtils.certFingerprint(cert1)).isNotEqualTo(CertUtils.certFingerprint(cert2));
    }

    @Test
    void isSelfSignedTrueForSelfSignedCert() throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("RSA", "BC").generateKeyPair();
        X509Certificate root = TestCertUtils.generateCACert(
                new org.bouncycastle.asn1.x500.X500Name("CN=Root"),
                kp,
                new org.bouncycastle.asn1.x500.X500Name("CN=Root"));
        assertThat(CertUtils.isSelfSigned(root)).isTrue();
    }

    @Test
    void isSelfSignedFalseForIssuedCert() throws Exception {
        KeyPair rootKP = KeyPairGenerator.getInstance("RSA", "BC").generateKeyPair();
        X509Certificate root = TestCertUtils.generateCACert(
                new org.bouncycastle.asn1.x500.X500Name("CN=Root"),
                rootKP,
                new org.bouncycastle.asn1.x500.X500Name("CN=Root"));

        X509Certificate child = TestCertUtils.generateEndEntityCert(
                new org.bouncycastle.asn1.x500.X500Name("CN=Child"),
                KeyPairGenerator.getInstance("RSA", "BC").generateKeyPair(),
                new org.bouncycastle.asn1.x500.X500Name("CN=Root"),
                rootKP.getPublic());

        assertThat(CertUtils.isSelfSigned(child)).isFalse();
    }

    @Test
    void skiAndSubKeyIdentifierReturnSameValue() throws Exception {
        X509Certificate cert = TestCertUtils.loadCertFromResources("2F0CB09BE3550EF17EC4F29C90ABD18BFCAAD63A.cer");
        byte[] ski1 = CertUtils.getSubjectKeyIdentifier(cert);
        byte[] ski2 = CertUtils.getSubjectKeyIdentifier(cert);
        assertThat(ski1).isNotNull();
        assertThat(ski2).isNotNull();
        assertThat(ski1).isEqualTo(ski2);
    }
}
