package svkreml.certificateViewer.gui.certificateParser;

import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;
import svkreml.certificateViewer.gui.api.model.CertificateModel;
import svkreml.certificateViewer.gui.api.model.CertificateStatus;
import svkreml.certificateViewer.gui.localization.ru.Localization;

import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;

class CertificateParserValidateTest {

    @Test
    void validateSelfSignedCertFromResources() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        X509CertificateHolder holder = loadCertFromResources("2F0CB09BE3550EF17EC4F29C90ABD18BFCAAD63A.cer");

        Localization localization = new Localization();
        localization.TSL_LOCATION_BKS = createTempBksWithCert(holder);

        CertificateParser.Validate validate = new CertificateParser.Validate(localization, holder);
        validate.invoke();

        assertThat(validate).isNotNull();
        assertThat(validate.getVerificationDetails()).isNotNull();
        assertThat(validate.getCertificateStatus())
                .isIn(CertificateStatus.TRUSTED, CertificateStatus.BROKEN, CertificateStatus.UNTRUSTED_ROOT);
        assertThat(validate.getCertificateChains()).isNotNull();
        assertThat(validate.getCertificateChains()).isNotEmpty();
    }

    @Test
    void validateIssuedCertWithoutChainInKeystore() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        X509CertificateHolder holder = loadCertFromResources("1D13121735DD6E1F59EA58C786B8F7E8B7E6E20F.cer");

        Localization localization = new Localization();
        localization.TSL_LOCATION_BKS = createTempBksWithCert(holder);

        CertificateParser.Validate validate = new CertificateParser.Validate(localization, holder);
        validate.invoke();

        assertThat(validate).isNotNull();
        assertThat(validate.getVerificationDetails()).isNotNull();
        assertThat(validate.getCertificateStatus())
                .isIn(CertificateStatus.UNTRUSTED_ROOT, CertificateStatus.BROKEN);
        assertThat(validate.getCertificateChains()).isNotNull();
        assertThat(validate.getCertificateChains()).isNotEmpty();
    }

    @Test
    void validatePopulatesChainDetails() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        X509CertificateHolder holder = loadCertFromResources("2F0CB09BE3550EF17EC4F29C90ABD18BFCAAD63A.cer");

        Localization localization = new Localization();
        localization.TSL_LOCATION_BKS = createTempBksWithCert(holder);

        CertificateParser.Validate validate = new CertificateParser.Validate(localization, holder);
        validate.invoke();

        for (CertificateModel.CertificateChain chain : validate.getCertificateChains()) {
            assertThat(chain.getCn()).isNotNull();
            assertThat(chain.getCertificateStatus()).isNotNull();
            assertThat(chain.getX509CertificateHolder()).isNotNull();
            assertThat(chain.getList()).isNotNull();
        }
    }

    @Test
    void validateBothResourceCerts() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        X509CertificateHolder selfSigned = loadCertFromResources("2F0CB09BE3550EF17EC4F29C90ABD18BFCAAD63A.cer");
        X509CertificateHolder issued = loadCertFromResources("1D13121735DD6E1F59EA58C786B8F7E8B7E6E20F.cer");

        Localization localization = new Localization();
        localization.TSL_LOCATION_BKS = createTempBksWithMultipleCerts(selfSigned, issued);

        CertificateParser.Validate validateSelfSigned = new CertificateParser.Validate(localization, selfSigned);
        validateSelfSigned.invoke();

        assertThat(validateSelfSigned.getCertificateStatus())
                .isIn(CertificateStatus.TRUSTED, CertificateStatus.BROKEN, CertificateStatus.UNTRUSTED_ROOT);

        CertificateParser.Validate validateIssued = new CertificateParser.Validate(localization, issued);
        validateIssued.invoke();

        assertThat(validateIssued.getCertificateStatus())
                .isIn(CertificateStatus.TRUSTED, CertificateStatus.BROKEN, CertificateStatus.UNTRUSTED_ROOT);
    }

    private X509CertificateHolder loadCertFromResources(String fileName) throws Exception {
        byte[] certBytes = Files.readAllBytes(new File("src/test/resources/" + fileName).toPath());
        X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(certBytes));
        return new X509CertificateHolder(cert.getEncoded());
    }

    private String createTempBksWithCert(X509CertificateHolder holder) throws Exception {
        KeyStore bks = KeyStore.getInstance("BKS", "BC");
        bks.load(null, "cgvybtunm,ovgcfre".toCharArray());

        X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(holder.getEncoded()));

        byte[] ski = getSki(cert);
        if (ski != null) {
            bks.setCertificateEntry(Hex.toHexString(ski), cert);
        }

        byte[] keyBytes = ("" + System.currentTimeMillis()).getBytes();
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
        bks.setEntry("info", new KeyStore.SecretKeyEntry(secretKey),
                new KeyStore.PasswordProtection("creation date".toCharArray()));

        File tempBks = File.createTempFile("test-validate-", ".bks");
        tempBks.deleteOnExit();
        bks.store(new FileOutputStream(tempBks), "cgvybtunm,ovgcfre".toCharArray());
        return tempBks.getAbsolutePath();
    }

    private String createTempBksWithMultipleCerts(X509CertificateHolder... holders) throws Exception {
        KeyStore bks = KeyStore.getInstance("BKS", "BC");
        bks.load(null, "cgvybtunm,ovgcfre".toCharArray());

        for (X509CertificateHolder holder : holders) {
            X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(holder.getEncoded()));
            byte[] ski = getSki(cert);
            if (ski != null) {
                bks.setCertificateEntry(Hex.toHexString(ski), cert);
            }
        }

        byte[] keyBytes = ("" + System.currentTimeMillis()).getBytes();
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
        bks.setEntry("info", new KeyStore.SecretKeyEntry(secretKey),
                new KeyStore.PasswordProtection("creation date".toCharArray()));

        File tempBks = File.createTempFile("test-validate-multi-", ".bks");
        tempBks.deleteOnExit();
        bks.store(new FileOutputStream(tempBks), "cgvybtunm,ovgcfre".toCharArray());
        return tempBks.getAbsolutePath();
    }

    private byte[] getSki(X509Certificate cert) throws Exception {
        byte[] value = cert.getExtensionValue("2.5.29.14");
        if (value == null) return null;
        return SubjectKeyIdentifier.getInstance(
                org.bouncycastle.asn1.ASN1OctetString.getInstance(value).getOctets()
        ).getKeyIdentifier();
    }
}
