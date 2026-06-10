package svkreml.certificateViewer.gui.certificateParser;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;
import svkreml.certificateViewer.gui.localization.ru.Localization;

import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class TrustChainBuilderTest {

    @Test
    void smallInitFindsChainInKeystore() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(2048);

        KeyPair rootKP = keyGen.generateKeyPair();
        X500Name rootDn = new X500Name("CN=Root Test CA, O=Test, C=RU");
        X509Certificate rootCert = generateCACert(rootDn, rootKP, rootDn);

        KeyPair interKP = keyGen.generateKeyPair();
        X500Name interDn = new X500Name("CN=Intermediate Test CA, O=Test, C=RU");
        X509Certificate interCert = generateCACert(interDn, interKP, rootDn, rootKP.getPublic());

        KeyPair leafKP = keyGen.generateKeyPair();
        X500Name leafDn = new X500Name("CN=Leaf Test Cert, O=Test, C=RU");
        X509Certificate leafCert = generateEndEntityCert(leafDn, leafKP, interDn, interKP.getPublic());

        KeyStore bks = KeyStore.getInstance("BKS", "BC");
        bks.load(null, "cgvybtunm,ovgcfre".toCharArray());

        bks.setCertificateEntry(
                Hex.toHexString(getSki(rootCert)),
                rootCert);
        bks.setCertificateEntry(
                Hex.toHexString(getSki(interCert)),
                interCert);
        bks.setCertificateEntry(
                Hex.toHexString(getSki(leafCert)),
                leafCert);

        byte[] keyBytes = ("" + System.currentTimeMillis()).getBytes();
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
        bks.setEntry("info", new KeyStore.SecretKeyEntry(secretKey),
                new KeyStore.PasswordProtection("creation date".toCharArray()));

        File tempBks = File.createTempFile("test-tsl", ".bks");
        tempBks.deleteOnExit();
        bks.store(new FileOutputStream(tempBks), "cgvybtunm,ovgcfre".toCharArray());

        Localization localization = new Localization();
        localization.TSL_LOCATION_BKS = tempBks.getAbsolutePath();

        Set<X509Certificate> chain = TrustChainBuilder.smallInit(localization, leafCert);

        assertThat(chain).hasSize(2);
        assertThat(chain).extracting(X509Certificate::getSubjectX500Principal)
                .containsExactlyInAnyOrder(interCert.getSubjectX500Principal(), rootCert.getSubjectX500Principal());
    }

    private X509Certificate generateCACert(X500Name subject, KeyPair keyPair, X500Name issuer) throws Exception {
        return generateCACert(subject, keyPair, issuer, null);
    }

    private X509Certificate generateCACert(X500Name subject, KeyPair keyPair, X500Name issuer, PublicKey issuerPublicKey) throws Exception {
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer,
                BigInteger.valueOf(System.currentTimeMillis()),
                new Date(),
                new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000),
                subject,
                keyPair.getPublic()
        );

      builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        SubjectKeyIdentifier ski = new SubjectKeyIdentifier(keyPair.getPublic().getEncoded());
        builder.addExtension(Extension.subjectKeyIdentifier, false, ski);

        PublicKey akiPublicKey = issuerPublicKey != null ? issuerPublicKey : keyPair.getPublic();
        AuthorityKeyIdentifier aki = new AuthorityKeyIdentifier(akiPublicKey.getEncoded());
        builder.addExtension(Extension.authorityKeyIdentifier, false, aki);

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
        return convertToX509Cert(builder.build(signer));
    }

    private X509Certificate generateEndEntityCert(X500Name subject, KeyPair keyPair, X500Name issuer, PublicKey issuerPublicKey) throws Exception {
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer,
                BigInteger.valueOf(System.currentTimeMillis()),
                new Date(),
                new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000),
                subject,
                keyPair.getPublic()
        );

        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        SubjectKeyIdentifier ski = new SubjectKeyIdentifier(keyPair.getPublic().getEncoded());
        builder.addExtension(Extension.subjectKeyIdentifier, false, ski);
        AuthorityKeyIdentifier aki = new AuthorityKeyIdentifier(issuerPublicKey.getEncoded());
        builder.addExtension(Extension.authorityKeyIdentifier, false, aki);

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
        return convertToX509Cert(builder.build(signer));
    }

    private X509Certificate convertToX509Cert(org.bouncycastle.cert.X509CertificateHolder holder) throws CertificateException, IOException {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) factory.generateCertificate(
                new ByteArrayInputStream(holder.getEncoded()));
    }

    private byte[] getSki(X509Certificate cert) throws Exception {
        byte[] value = cert.getExtensionValue(Extension.subjectKeyIdentifier.getId());
        if (value == null) return null;
        return SubjectKeyIdentifier.getInstance(
                org.bouncycastle.asn1.ASN1OctetString.getInstance(value).getOctets()
        ).getKeyIdentifier();
    }

    @Test
    void testCertificateFromResourcesIsInTsl() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        byte[] certBytes = Files.readAllBytes(new File("src/test/resources/1D13121735DD6E1F59EA58C786B8F7E8B7E6E20F.cer").toPath());
        X509Certificate testCert = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(certBytes));

        Localization localization = new Localization();
        Set<X509Certificate> tslCerts = TrustChainBuilder.gostTlsStore(localization);

        boolean found = tslCerts.stream()
                .anyMatch(c -> Arrays.equals(c.getSubjectX500Principal().getEncoded(),
                        testCert.getSubjectX500Principal().getEncoded()));

        assertThat(found)
                .as("Certificate 1D13121735DD6E1F59EA58C786B8F7E8B7E6E20F.cer should be present in current TSL")
                .isTrue();
    }
}
