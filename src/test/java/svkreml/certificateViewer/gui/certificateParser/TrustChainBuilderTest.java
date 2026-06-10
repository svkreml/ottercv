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
import java.util.Enumeration;
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

    @Test
    void smallInitFindsBothCertsWithSameSubjectAndSki() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(2048);

        KeyPair rootKP = keyGen.generateKeyPair();
        X500Name rootDn = new X500Name("CN=Root Test CA, O=Test, C=RU");
        X509Certificate rootCert = generateCACert(rootDn, rootKP, rootDn);

        KeyPair interKP = keyGen.generateKeyPair();
        X500Name interDn = new X500Name("CN=Intermediate Test CA, O=Test, C=RU");
        X509Certificate interCert1 = generateCACert(interDn, interKP, rootDn, rootKP.getPublic());

        X509Certificate interCert2 = generateEndEntityCert(interDn, interKP, rootDn, rootKP.getPublic());

        KeyPair leafKP = keyGen.generateKeyPair();
        X500Name leafDn = new X500Name("CN=Leaf Test Cert, O=Test, C=RU");
        X509Certificate leafCert = generateEndEntityCert(leafDn, leafKP, interDn, interKP.getPublic());

        assertThat(Hex.toHexString(getSki(interCert1)))
                .as("interCert1 and interCert2 must have the same SKI")
                .isEqualTo(Hex.toHexString(getSki(interCert2)));

        KeyStore bks = KeyStore.getInstance("BKS", "BC");
        bks.load(null, "cgvybtunm,ovgcfre".toCharArray());

        bks.setCertificateEntry(Hex.toHexString(getSki(rootCert)), rootCert);
        bks.setCertificateEntry(Hex.toHexString(getSki(interCert1)), interCert1);
        bks.setCertificateEntry(
                Hex.toHexString(getSki(interCert2)) + "\t" + Hex.toHexString(MessageDigest.getInstance("SHA-256").digest(interCert2.getEncoded())),
                interCert2);
        bks.setCertificateEntry(Hex.toHexString(getSki(leafCert)), leafCert);

        byte[] keyBytes = ("" + System.currentTimeMillis()).getBytes();
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
        bks.setEntry("info", new KeyStore.SecretKeyEntry(secretKey),
                new KeyStore.PasswordProtection("creation date".toCharArray()));

        File tempBks = File.createTempFile("test-tsl-dup", ".bks");
        tempBks.deleteOnExit();
        bks.store(new FileOutputStream(tempBks), "cgvybtunm,ovgcfre".toCharArray());

        Localization localization = new Localization();
        localization.TSL_LOCATION_BKS = tempBks.getAbsolutePath();

        Set<X509Certificate> chain = TrustChainBuilder.smallInit(localization, leafCert);

        assertThat(chain).hasSizeGreaterThanOrEqualTo(2);
        boolean hasInterCert1 = chain.stream()
                .anyMatch(c -> c.getSubjectX500Principal().equals(interCert1.getSubjectX500Principal())
                        && Arrays.equals(c.getPublicKey().getEncoded(), interCert1.getPublicKey().getEncoded()));
        boolean hasInterCert2 = chain.stream()
                .anyMatch(c -> c.getSubjectX500Principal().equals(interCert2.getSubjectX500Principal())
                        && Arrays.equals(c.getPublicKey().getEncoded(), interCert2.getPublicKey().getEncoded()));
        assertThat(hasInterCert1).as("Chain should contain first intermediate cert").isTrue();
        assertThat(hasInterCert2).as("Chain should contain second intermediate cert").isTrue();
    }

    @Test
    void smallInitDisambiguatesCrossCertByIssuer() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(2048);

        KeyPair aKP = keyGen.generateKeyPair();
        X500Name aDn = new X500Name("CN=CA A, O=Test, C=RU");
        X509Certificate aSelfSigned = generateCACert(aDn, aKP, aDn);

        KeyPair bKP = keyGen.generateKeyPair();
        X500Name bDn = new X500Name("CN=CA B, O=Test, C=RU");
        X509Certificate crossCertBA = generateCrossCert(aDn, aKP, bDn, bKP);

        assertThat(Hex.toHexString(getSki(aSelfSigned)))
                .as("Self-signed and cross-cert must have the same SKI (same public key)")
                .isEqualTo(Hex.toHexString(getSki(crossCertBA)));
        assertThat(aSelfSigned.getIssuerX500Principal())
                .as("Self-signed Issuer must differ from cross-cert Issuer")
                .isNotEqualTo(crossCertBA.getIssuerX500Principal());

        KeyStore bks = KeyStore.getInstance("BKS", "BC");
        bks.load(null, "cgvybtunm,ovgcfre".toCharArray());

        bks.setCertificateEntry(Hex.toHexString(getSki(aSelfSigned)), aSelfSigned);
        bks.setCertificateEntry(
                Hex.toHexString(getSki(crossCertBA)) + "\t" + Hex.toHexString(MessageDigest.getInstance("SHA-256").digest(crossCertBA.getEncoded())),
                crossCertBA);

        byte[] keyBytes = ("" + System.currentTimeMillis()).getBytes();
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
        bks.setEntry("info", new KeyStore.SecretKeyEntry(secretKey),
                new KeyStore.PasswordProtection("creation date".toCharArray()));

        File tempBks = File.createTempFile("test-tsl-cross", ".bks");
        tempBks.deleteOnExit();
        bks.store(new FileOutputStream(tempBks), "cgvybtunm,ovgcfre".toCharArray());

        Localization localization = new Localization();
        localization.TSL_LOCATION_BKS = tempBks.getAbsolutePath();

        Set<X509Certificate> chain = TrustChainBuilder.smallInit(localization, aSelfSigned);

        assertThat(chain).hasSize(1);
        X509Certificate found = chain.iterator().next();
        assertThat(found.getIssuerX500Principal())
                .as("Chain must contain self-signed A->A, not cross-cert B->A")
                .isEqualTo(aSelfSigned.getIssuerX500Principal());
        assertThat(found.getSubjectX500Principal())
                .isEqualTo(aSelfSigned.getSubjectX500Principal());
    }

    private X509Certificate generateCrossCert(X500Name subject, KeyPair subjectKeyPair,
                                               X500Name issuer, KeyPair issuerKeyPair) throws Exception {
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer,
                BigInteger.valueOf(System.currentTimeMillis()),
                new Date(),
                new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000),
                subject,
                subjectKeyPair.getPublic()
        );

        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        SubjectKeyIdentifier ski = new SubjectKeyIdentifier(subjectKeyPair.getPublic().getEncoded());
        builder.addExtension(Extension.subjectKeyIdentifier, false, ski);
        AuthorityKeyIdentifier aki = new AuthorityKeyIdentifier(issuerKeyPair.getPublic().getEncoded());
        builder.addExtension(Extension.authorityKeyIdentifier, false, aki);

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(issuerKeyPair.getPrivate());
        return convertToX509Cert(builder.build(signer));
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
    void smallInitFindsRootInCaFolderWithDifferentAlias() throws Exception {
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

        byte[] rootSki = getSki(rootCert);
        byte[] interSki = getSki(interCert);

        bks.setCertificateEntry(Hex.toHexString(interSki), interCert);

        String caFolderAlias = CustomBCStyle.INSTANCE.toString(
                org.bouncycastle.asn1.x500.X500Name.getInstance(rootCert.getSubjectX500Principal().getEncoded()))
                + " " + Hex.toHexString(rootSki);
        bks.setCertificateEntry(caFolderAlias, rootCert);

        byte[] keyBytes = ("" + System.currentTimeMillis()).getBytes();
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
        bks.setEntry("info", new KeyStore.SecretKeyEntry(secretKey),
                new KeyStore.PasswordProtection("creation date".toCharArray()));

        File tempBks = File.createTempFile("test-tsl-ca", ".bks");
        tempBks.deleteOnExit();
        bks.store(new FileOutputStream(tempBks), "cgvybtunm,ovgcfre".toCharArray());

        Localization localization = new Localization();
        localization.TSL_LOCATION_BKS = tempBks.getAbsolutePath();

        Set<X509Certificate> chain = TrustChainBuilder.smallInit(localization, leafCert);

        assertThat(chain).hasSize(2);
        assertThat(chain).extracting(X509Certificate::getSubjectX500Principal)
                .containsExactlyInAnyOrder(interCert.getSubjectX500Principal(), rootCert.getSubjectX500Principal());
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

    @Test
    void smallInitBuildsChainForFedKaznacheistvo() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        X509Certificate fkCert = loadCertFromResources("12BC42082D3F6027A29B7A87FE09B0329631C076.cer");
        X509Certificate minCifrySelfSigned = loadCertFromResources("2F0CB09BE3550EF17EC4F29C90ABD18BFCAAD63A.cer");

        assertThat(fkCert.getIssuerX500Principal())
                .isEqualTo(minCifrySelfSigned.getSubjectX500Principal());

        byte[] fkAki = TrustChainBuilder.getSubjectKeyIdentifier(minCifrySelfSigned);
        assertThat(fkAki).isNotNull();

        KeyStore bks = KeyStore.getInstance("BKS", "BC");
        bks.load(null, "cgvybtunm,ovgcfre".toCharArray());
        bks.setCertificateEntry(
                Hex.toHexString(TrustChainBuilder.getSubjectKeyIdentifier(minCifrySelfSigned)),
                minCifrySelfSigned);

        byte[] keyBytes = ("" + System.currentTimeMillis()).getBytes();
        bks.setEntry("info", new KeyStore.SecretKeyEntry(new SecretKeySpec(keyBytes, "AES")),
                new KeyStore.PasswordProtection("creation date".toCharArray()));

        File tempBks = File.createTempFile("test-fk-chain", ".bks");
        tempBks.deleteOnExit();
        bks.store(new FileOutputStream(tempBks), "cgvybtunm,ovgcfre".toCharArray());

        Localization localization = new Localization();
        localization.TSL_LOCATION_BKS = tempBks.getAbsolutePath();

        Set<X509Certificate> chain = TrustChainBuilder.smallInit(localization, fkCert);

        assertThat(chain).as("Chain for FK cert should not be empty").isNotEmpty();
        assertThat(chain).extracting(X509Certificate::getSubjectX500Principal)
                .anyMatch(s -> s.equals(minCifrySelfSigned.getSubjectX500Principal()));
    }

    @Test
    void smallInitBuildsChainForFedKaznacheistvoWithCrossCert() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        X509Certificate fkCert = loadCertFromResources("12BC42082D3F6027A29B7A87FE09B0329631C076.cer");
        X509Certificate minCifrySelfSigned = loadCertFromResources("2F0CB09BE3550EF17EC4F29C90ABD18BFCAAD63A.cer");
        X509Certificate minCifryCrossCert = loadCertFromResources("1D13121735DD6E1F59EA58C786B8F7E8B7E6E20F.cer");

        assertThat(Hex.toHexString(TrustChainBuilder.getSubjectKeyIdentifier(minCifrySelfSigned)))
                .as("Self-signed and cross-cert must have same SKI")
                .isEqualTo(Hex.toHexString(TrustChainBuilder.getSubjectKeyIdentifier(minCifryCrossCert)));

        KeyStore bks = KeyStore.getInstance("BKS", "BC");
        bks.load(null, "cgvybtunm,ovgcfre".toCharArray());
        bks.setCertificateEntry(
                Hex.toHexString(TrustChainBuilder.getSubjectKeyIdentifier(minCifrySelfSigned)),
                minCifrySelfSigned);
        bks.setCertificateEntry(
                Hex.toHexString(TrustChainBuilder.getSubjectKeyIdentifier(minCifryCrossCert)) + "-cross",
                minCifryCrossCert);

        byte[] keyBytes = ("" + System.currentTimeMillis()).getBytes();
        bks.setEntry("info", new KeyStore.SecretKeyEntry(new SecretKeySpec(keyBytes, "AES")),
                new KeyStore.PasswordProtection("creation date".toCharArray()));

        File tempBks = File.createTempFile("test-fk-cross", ".bks");
        tempBks.deleteOnExit();
        bks.store(new FileOutputStream(tempBks), "cgvybtunm,ovgcfre".toCharArray());

        Localization localization = new Localization();
        localization.TSL_LOCATION_BKS = tempBks.getAbsolutePath();

        Set<X509Certificate> chain = TrustChainBuilder.smallInit(localization, fkCert);

        assertThat(chain).as("Chain for FK cert should not be empty").isNotEmpty();
        boolean hasSelfSigned = chain.stream()
                .anyMatch(c -> c.getSubjectX500Principal().equals(minCifrySelfSigned.getSubjectX500Principal())
                        && c.getIssuerX500Principal().equals(minCifrySelfSigned.getIssuerX500Principal()));
        assertThat(hasSelfSigned).as("Chain should contain the self-signed Минцифры cert").isTrue();
    }

    private X509Certificate loadCertFromResources(String fileName) throws Exception {
        byte[] certBytes = Files.readAllBytes(new File("src/test/resources/" + fileName).toPath());
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(certBytes));
    }
}
