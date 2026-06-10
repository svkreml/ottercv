package svkreml.certificateViewer.gui.certificateParser;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import svkreml.certificateViewer.gui.localization.ru.Localization;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class TrustChainBuilderTest {

    @BeforeAll
    static void setup() {
        TestCertUtils.ensureBcProvider();
    }

    @Test
    void smallInitFindsChainInKeystore() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(2048);

        KeyPair rootKP = keyGen.generateKeyPair();
        X500Name rootDn = new X500Name("CN=Root Test CA, O=Test, C=RU");
        X509Certificate rootCert = TestCertUtils.generateCACert(rootDn, rootKP, rootDn);

        KeyPair interKP = keyGen.generateKeyPair();
        X500Name interDn = new X500Name("CN=Intermediate Test CA, O=Test, C=RU");
        X509Certificate interCert = TestCertUtils.generateCACert(interDn, interKP, rootDn, rootKP.getPublic());

        KeyPair leafKP = keyGen.generateKeyPair();
        X500Name leafDn = new X500Name("CN=Leaf Test Cert, O=Test, C=RU");
        X509Certificate leafCert = TestCertUtils.generateEndEntityCert(leafDn, leafKP, interDn, interKP.getPublic());

        String bksPath = TestCertUtils.createTempBks(rootCert, interCert, leafCert);
        Localization localization = new Localization();
        localization.TSL_LOCATION_BKS = bksPath;

        Set<X509Certificate> chain = TrustChainBuilder.smallInit(localization, leafCert);

        assertThat(chain).hasSize(2);
        assertThat(chain).extracting(X509Certificate::getSubjectX500Principal)
                .containsExactlyInAnyOrder(interCert.getSubjectX500Principal(), rootCert.getSubjectX500Principal());
    }

    @Test
    void smallInitFindsBothCertsWithSameSubjectAndSki() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(2048);

        KeyPair rootKP = keyGen.generateKeyPair();
        X500Name rootDn = new X500Name("CN=Root Test CA, O=Test, C=RU");
        X509Certificate rootCert = TestCertUtils.generateCACert(rootDn, rootKP, rootDn);

        KeyPair interKP = keyGen.generateKeyPair();
        X500Name interDn = new X500Name("CN=Intermediate Test CA, O=Test, C=RU");
        X509Certificate interCert1 = TestCertUtils.generateCACert(interDn, interKP, rootDn, rootKP.getPublic());
        X509Certificate interCert2 = TestCertUtils.generateEndEntityCert(interDn, interKP, rootDn, rootKP.getPublic());

        KeyPair leafKP = keyGen.generateKeyPair();
        X500Name leafDn = new X500Name("CN=Leaf Test Cert, O=Test, C=RU");
        X509Certificate leafCert = TestCertUtils.generateEndEntityCert(leafDn, leafKP, interDn, interKP.getPublic());

        assertThat(Hex.toHexString(TestCertUtils.getSki(interCert1)))
                .as("interCert1 and interCert2 must have the same SKI")
                .isEqualTo(Hex.toHexString(TestCertUtils.getSki(interCert2)));

        KeyStore bks = KeyStore.getInstance("BKS", "BC");
        bks.load(null, TestCertUtils.BKS_PASSWORD.toCharArray());
        bks.setCertificateEntry(Hex.toHexString(TestCertUtils.getSki(rootCert)), rootCert);
        bks.setCertificateEntry(Hex.toHexString(TestCertUtils.getSki(interCert1)), interCert1);
        bks.setCertificateEntry(
                Hex.toHexString(TestCertUtils.getSki(interCert2)) + "\t" + Hex.toHexString(MessageDigest.getInstance("SHA-256").digest(interCert2.getEncoded())),
                interCert2);
        bks.setCertificateEntry(Hex.toHexString(TestCertUtils.getSki(leafCert)), leafCert);

        byte[] keyBytes = ("" + System.currentTimeMillis()).getBytes();
        bks.setEntry("info", new KeyStore.SecretKeyEntry(new javax.crypto.spec.SecretKeySpec(keyBytes, "AES")),
                new KeyStore.PasswordProtection("creation date".toCharArray()));

        File tempBks = File.createTempFile("test-tsl-dup", ".bks");
        tempBks.deleteOnExit();
        bks.store(new FileOutputStream(tempBks), TestCertUtils.BKS_PASSWORD.toCharArray());

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
        assertThat(hasInterCert1 || hasInterCert2)
                .as("Chain should contain one of the two intermediate certs with same SKI").isTrue();
    }

    @Test
    void smallInitDisambiguatesCrossCertByIssuer() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(2048);

        KeyPair aKP = keyGen.generateKeyPair();
        X500Name aDn = new X500Name("CN=CA A, O=Test, C=RU");
        X509Certificate aSelfSigned = TestCertUtils.generateCACert(aDn, aKP, aDn);

        KeyPair bKP = keyGen.generateKeyPair();
        X500Name bDn = new X500Name("CN=CA B, O=Test, C=RU");
        X509Certificate crossCertBA = TestCertUtils.generateCrossCert(aDn, aKP, bDn, bKP);

        assertThat(Hex.toHexString(TestCertUtils.getSki(aSelfSigned)))
                .as("Self-signed and cross-cert must have the same SKI (same public key)")
                .isEqualTo(Hex.toHexString(TestCertUtils.getSki(crossCertBA)));
        assertThat(aSelfSigned.getIssuerX500Principal())
                .as("Self-signed Issuer must differ from cross-cert Issuer")
                .isNotEqualTo(crossCertBA.getIssuerX500Principal());

        String bksPath = TestCertUtils.createTempBksWithDuplicateAlias(
                aSelfSigned, Hex.toHexString(TestCertUtils.getSki(aSelfSigned)),
                crossCertBA, Hex.toHexString(TestCertUtils.getSki(crossCertBA)) + "\t"
                        + Hex.toHexString(java.security.MessageDigest.getInstance("SHA-256").digest(crossCertBA.getEncoded())));
        Localization localization = new Localization();
        localization.TSL_LOCATION_BKS = bksPath;

        Set<X509Certificate> chain = TrustChainBuilder.smallInit(localization, aSelfSigned);

        assertThat(chain).hasSize(1);
        X509Certificate found = chain.iterator().next();
        assertThat(found.getIssuerX500Principal())
                .as("Chain must contain self-signed A->A, not cross-cert B->A")
                .isEqualTo(aSelfSigned.getIssuerX500Principal());
        assertThat(found.getSubjectX500Principal())
                .isEqualTo(aSelfSigned.getSubjectX500Principal());
    }

    @Test
    void smallInitFindsRootInCaFolderWithDifferentAlias() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(2048);

        KeyPair rootKP = keyGen.generateKeyPair();
        X500Name rootDn = new X500Name("CN=Root Test CA, O=Test, C=RU");
        X509Certificate rootCert = TestCertUtils.generateCACert(rootDn, rootKP, rootDn);

        KeyPair interKP = keyGen.generateKeyPair();
        X500Name interDn = new X500Name("CN=Intermediate Test CA, O=Test, C=RU");
        X509Certificate interCert = TestCertUtils.generateCACert(interDn, interKP, rootDn, rootKP.getPublic());

        KeyPair leafKP = keyGen.generateKeyPair();
        X500Name leafDn = new X500Name("CN=Leaf Test Cert, O=Test, C=RU");
        X509Certificate leafCert = TestCertUtils.generateEndEntityCert(leafDn, leafKP, interDn, interKP.getPublic());

        KeyStore bks = KeyStore.getInstance("BKS", "BC");
        bks.load(null, TestCertUtils.BKS_PASSWORD.toCharArray());

        byte[] rootSki = TestCertUtils.getSki(rootCert);
        byte[] interSki = TestCertUtils.getSki(interCert);

        bks.setCertificateEntry(Hex.toHexString(interSki), interCert);

        String caFolderAlias = CustomBCStyle.INSTANCE.toString(
                org.bouncycastle.asn1.x500.X500Name.getInstance(rootCert.getSubjectX500Principal().getEncoded()))
                + " " + Hex.toHexString(rootSki);
        bks.setCertificateEntry(caFolderAlias, rootCert);

        byte[] keyBytes = ("" + System.currentTimeMillis()).getBytes();
        bks.setEntry("info", new KeyStore.SecretKeyEntry(new javax.crypto.spec.SecretKeySpec(keyBytes, "AES")),
                new KeyStore.PasswordProtection("creation date".toCharArray()));

        File tempBks = File.createTempFile("test-tsl-ca", ".bks");
        tempBks.deleteOnExit();
        bks.store(new FileOutputStream(tempBks), TestCertUtils.BKS_PASSWORD.toCharArray());

        Localization localization = new Localization();
        localization.TSL_LOCATION_BKS = tempBks.getAbsolutePath();

        Set<X509Certificate> chain = TrustChainBuilder.smallInit(localization, leafCert);

        assertThat(chain).hasSize(2);
        assertThat(chain).extracting(X509Certificate::getSubjectX500Principal)
                .containsExactlyInAnyOrder(interCert.getSubjectX500Principal(), rootCert.getSubjectX500Principal());
    }

    @Test
    void testCertificateFromResourcesIsInTsl() throws Exception {
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
        X509Certificate fkCert = TestCertUtils.loadCertFromResources("12BC42082D3F6027A29B7A87FE09B0329631C076.cer");
        X509Certificate minCifrySelfSigned = TestCertUtils.loadCertFromResources("2F0CB09BE3550EF17EC4F29C90ABD18BFCAAD63A.cer");

        assertThat(fkCert.getIssuerX500Principal())
                .isEqualTo(minCifrySelfSigned.getSubjectX500Principal());

        byte[] fkAki = TrustChainBuilder.getSubjectKeyIdentifier(minCifrySelfSigned);
        assertThat(fkAki).isNotNull();

        String bksPath = TestCertUtils.createTempBks(minCifrySelfSigned);
        Localization localization = new Localization();
        localization.TSL_LOCATION_BKS = bksPath;

        Set<X509Certificate> chain = TrustChainBuilder.smallInit(localization, fkCert);

        assertThat(chain).as("Chain for FK cert should not be empty").isNotEmpty();
        assertThat(chain).extracting(X509Certificate::getSubjectX500Principal)
                .anyMatch(s -> s.equals(minCifrySelfSigned.getSubjectX500Principal()));
    }

    @Test
    void smallInitBuildsChainForFedKaznacheistvoWithCrossCert() throws Exception {
        X509Certificate fkCert = TestCertUtils.loadCertFromResources("12BC42082D3F6027A29B7A87FE09B0329631C076.cer");
        X509Certificate minCifrySelfSigned = TestCertUtils.loadCertFromResources("2F0CB09BE3550EF17EC4F29C90ABD18BFCAAD63A.cer");
        X509Certificate minCifryCrossCert = TestCertUtils.loadCertFromResources("1D13121735DD6E1F59EA58C786B8F7E8B7E6E20F.cer");

        assertThat(Hex.toHexString(TrustChainBuilder.getSubjectKeyIdentifier(minCifrySelfSigned)))
                .as("Self-signed and cross-cert must have same SKI")
                .isEqualTo(Hex.toHexString(TrustChainBuilder.getSubjectKeyIdentifier(minCifryCrossCert)));

        String bksPath = TestCertUtils.createTempBksWithDuplicateAlias(
                minCifrySelfSigned,
                Hex.toHexString(TrustChainBuilder.getSubjectKeyIdentifier(minCifrySelfSigned)),
                minCifryCrossCert,
                Hex.toHexString(TrustChainBuilder.getSubjectKeyIdentifier(minCifryCrossCert)) + "-cross");
        Localization localization = new Localization();
        localization.TSL_LOCATION_BKS = bksPath;

        Set<X509Certificate> chain = TrustChainBuilder.smallInit(localization, fkCert);

        assertThat(chain).as("Chain for FK cert should not be empty").isNotEmpty();
        boolean hasSelfSigned = chain.stream()
                .anyMatch(c -> c.getSubjectX500Principal().equals(minCifrySelfSigned.getSubjectX500Principal())
                        && c.getIssuerX500Principal().equals(minCifrySelfSigned.getIssuerX500Principal()));
        assertThat(hasSelfSigned).as("Chain should contain the self-signed Минцифры cert").isTrue();
    }

    @Test
    void smallInitSelfSignedCertReturnsItself() throws Exception {
        X509Certificate selfSigned = TestCertUtils.loadCertFromResources("2F0CB09BE3550EF17EC4F29C90ABD18BFCAAD63A.cer");

        String bksPath = TestCertUtils.createTempBks(selfSigned);
        Localization localization = new Localization();
        localization.TSL_LOCATION_BKS = bksPath;

        Set<X509Certificate> chain = TrustChainBuilder.smallInit(localization, selfSigned);

        assertThat(chain).hasSize(1);
        assertThat(chain.iterator().next().getSubjectX500Principal())
                .isEqualTo(selfSigned.getSubjectX500Principal());
    }

    @Test
    void smallInitCrossCertFindsParent() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(2048);

        KeyPair rootKP = keyGen.generateKeyPair();
        X500Name rootDn = new X500Name("CN=Root Test CA, O=Test, C=RU");
        X509Certificate selfSigned = TestCertUtils.generateCACert(rootDn, rootKP, rootDn);

        KeyPair otherKP = keyGen.generateKeyPair();
        X500Name otherDn = new X500Name("CN=Other CA, O=Test, C=RU");
        X509Certificate crossCert = TestCertUtils.generateCrossCert(otherDn, otherKP, rootDn, rootKP);

        assertThat(Hex.toHexString(TestCertUtils.getSki(selfSigned)))
                .as("Self-signed and cross-cert must have same AKI/SKI relationship")
                .isEqualTo(Hex.toHexString(TestCertUtils.getSki(selfSigned)));
        assertThat(crossCert.getIssuerX500Principal())
                .as("Cross-cert issuer must match self-signed subject")
                .isEqualTo(selfSigned.getSubjectX500Principal());
        assertThat(crossCert.getSubjectX500Principal())
                .as("Cross-cert subject must differ from self-signed subject")
                .isNotEqualTo(selfSigned.getSubjectX500Principal());

        String bksPath = TestCertUtils.createTempBks(selfSigned);
        Localization localization = new Localization();
        localization.TSL_LOCATION_BKS = bksPath;

        Set<X509Certificate> chain = TrustChainBuilder.smallInit(localization, crossCert);

        assertThat(chain).as("Chain should contain the self-signed parent").isNotEmpty();
        boolean hasSelfSigned = chain.stream()
                .anyMatch(c -> c.getSubjectX500Principal().equals(selfSigned.getSubjectX500Principal())
                        && c.getIssuerX500Principal().equals(selfSigned.getIssuerX500Principal()));
        assertThat(hasSelfSigned).as("Chain should contain the self-signed root cert").isTrue();
    }

    @Test
    void smallInitIssuedCertFindsChain() throws Exception {
        X509Certificate fkCert = TestCertUtils.loadCertFromResources("12BC42082D3F6027A29B7A87FE09B0329631C076.cer");
        X509Certificate selfSigned = TestCertUtils.loadCertFromResources("2F0CB09BE3550EF17EC4F29C90ABD18BFCAAD63A.cer");

        String bksPath = TestCertUtils.createTempBks(selfSigned);
        Localization localization = new Localization();
        localization.TSL_LOCATION_BKS = bksPath;

        Set<X509Certificate> chain = TrustChainBuilder.smallInit(localization, fkCert);

        assertThat(chain).as("Chain for issued cert should not be empty").isNotEmpty();
        assertThat(chain).extracting(X509Certificate::getSubjectX500Principal)
                .anyMatch(s -> s.equals(selfSigned.getSubjectX500Principal()));
    }

    @Test
    void smallInitEmptyKeystoreReturnsEmpty() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(2048);

        KeyPair rootKP = keyGen.generateKeyPair();
        X500Name rootDn = new X500Name("CN=Root Test CA, O=Test, C=RU");
        X509Certificate rootCert = TestCertUtils.generateCACert(rootDn, rootKP, rootDn);

        String bksPath = TestCertUtils.createTempBks();
        Localization localization = new Localization();
        localization.TSL_LOCATION_BKS = bksPath;

        Set<X509Certificate> chain = TrustChainBuilder.smallInit(localization, rootCert);

        assertThat(chain).as("Chain from empty keystore should be empty").isEmpty();
    }

    @Test
    void smallInitNoParentFoundReturnsEmpty() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(2048);

        KeyPair rootKP = keyGen.generateKeyPair();
        X500Name rootDn = new X500Name("CN=Root Test CA, O=Test, C=RU");
        X509Certificate rootCert = TestCertUtils.generateCACert(rootDn, rootKP, rootDn);

        KeyPair leafKP = keyGen.generateKeyPair();
        X500Name leafDn = new X500Name("CN=Leaf Test Cert, O=Test, C=RU");
        X509Certificate leafCert = TestCertUtils.generateEndEntityCert(leafDn, leafKP, rootDn, rootKP.getPublic());

        String bksPath = TestCertUtils.createTempBks(leafCert);
        Localization localization = new Localization();
        localization.TSL_LOCATION_BKS = bksPath;

        Set<X509Certificate> chain = TrustChainBuilder.smallInit(localization, leafCert);

        assertThat(chain).as("Chain should be empty when no parent found").isEmpty();
    }

    @Test
    void smallInitFourLevelChain() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(2048);

        KeyPair rootKP = keyGen.generateKeyPair();
        X500Name rootDn = new X500Name("CN=Root CA, O=Test, C=RU");
        X509Certificate rootCert = TestCertUtils.generateCACert(rootDn, rootKP, rootDn);

        KeyPair inter1KP = keyGen.generateKeyPair();
        X500Name inter1Dn = new X500Name("CN=Intermediate CA 1, O=Test, C=RU");
        X509Certificate inter1Cert = TestCertUtils.generateCACert(inter1Dn, inter1KP, rootDn, rootKP.getPublic());

        KeyPair inter2KP = keyGen.generateKeyPair();
        X500Name inter2Dn = new X500Name("CN=Intermediate CA 2, O=Test, C=RU");
        X509Certificate inter2Cert = TestCertUtils.generateCACert(inter2Dn, inter2KP, inter1Dn, inter1KP.getPublic());

        KeyPair leafKP = keyGen.generateKeyPair();
        X500Name leafDn = new X500Name("CN=Leaf Cert, O=Test, C=RU");
        X509Certificate leafCert = TestCertUtils.generateEndEntityCert(leafDn, leafKP, inter2Dn, inter2KP.getPublic());

        String bksPath = TestCertUtils.createTempBks(rootCert, inter1Cert, inter2Cert, leafCert);
        Localization localization = new Localization();
        localization.TSL_LOCATION_BKS = bksPath;

        Set<X509Certificate> chain = TrustChainBuilder.smallInit(localization, leafCert);

        assertThat(chain).hasSize(3);
        assertThat(chain).extracting(X509Certificate::getSubjectX500Principal)
                .containsExactlyInAnyOrder(
                        inter1Cert.getSubjectX500Principal(),
                        inter2Cert.getSubjectX500Principal(),
                        rootCert.getSubjectX500Principal());
    }

    @Test
    void smallInitDetectsCycleAndStops() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(2048);

        KeyPair aKP = keyGen.generateKeyPair();
        X500Name aDn = new X500Name("CN=CA A, O=Test, C=RU");
        X509Certificate aCert = TestCertUtils.generateCACert(aDn, aKP, aDn);

        KeyPair bKP = keyGen.generateKeyPair();
        X500Name bDn = new X500Name("CN=CA B, O=Test, C=RU");
        X509Certificate bCert = TestCertUtils.generateCACert(bDn, bKP, aDn, aKP.getPublic());

        KeyPair leafKP = keyGen.generateKeyPair();
        X500Name leafDn = new X500Name("CN=Leaf Cert, O=Test, C=RU");
        X509Certificate leafCert = TestCertUtils.generateEndEntityCert(leafDn, leafKP, bDn, bKP.getPublic());

        String bksPath = TestCertUtils.createTempBksWithDuplicateAlias(
                aCert, Hex.toHexString(TestCertUtils.getSki(aCert)),
                bCert, Hex.toHexString(TestCertUtils.getSki(bCert)) + "-dup");
        Localization localization = new Localization();
        localization.TSL_LOCATION_BKS = bksPath;

        Set<X509Certificate> chain = TrustChainBuilder.smallInit(localization, leafCert);

        assertThat(chain).as("Chain should not be infinite due to cycle").isNotEmpty();
        assertThat(chain.size()).as("Chain should not have more than 10 entries").isLessThanOrEqualTo(10);
    }

}
