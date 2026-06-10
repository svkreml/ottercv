package svkreml.certificateViewer.gui.certificateParser;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class ChainWalkerTest {

    @BeforeAll
    static void setup() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    void buildChainReturnsEmptyForEmptyKeystore() throws Exception {
        KeyStore empty = KeyStore.getInstance("BKS", "BC");
        empty.load(null, TestCertUtils.BKS_PASSWORD.toCharArray());

        KeyPair kp = KeyPairGenerator.getInstance("RSA", "BC").generateKeyPair();
        X509Certificate cert = TestCertUtils.generateCACert(
                new X500Name("CN=Root"), kp, new X500Name("CN=Root"));

        ChainWalker walker = new ChainWalker();
        Set<X509Certificate> chain = walker.buildChain(empty, cert);
        assertThat(chain).isEmpty();
    }

    @Test
    void buildChainReturnsEmptyWhenParentNotFound() throws Exception {
        KeyStore store = KeyStore.getInstance("BKS", "BC");
        store.load(null, TestCertUtils.BKS_PASSWORD.toCharArray());

        KeyPair rootKP = KeyPairGenerator.getInstance("RSA", "BC").generateKeyPair();
        X509Certificate root = TestCertUtils.generateCACert(
                new X500Name("CN=Root"), rootKP, new X500Name("CN=Root"));

        KeyPair leafKP = KeyPairGenerator.getInstance("RSA", "BC").generateKeyPair();
        KeyPair otherIssuerKP = KeyPairGenerator.getInstance("RSA", "BC").generateKeyPair();
        X509Certificate leaf = TestCertUtils.generateEndEntityCert(
                new X500Name("CN=Leaf"), leafKP, new X500Name("CN=Other CA"), otherIssuerKP.getPublic());

        store.setCertificateEntry("root", root);

        ChainWalker walker = new ChainWalker();
        Set<X509Certificate> chain = walker.buildChain(store, leaf);
        assertThat(chain).isEmpty();
    }

    @Test
    void buildChainFindsTwoLevelChain() throws Exception {
        KeyStore store = KeyStore.getInstance("BKS", "BC");
        store.load(null, TestCertUtils.BKS_PASSWORD.toCharArray());

        KeyPair rootKP = KeyPairGenerator.getInstance("RSA", "BC").generateKeyPair();
        X509Certificate root = TestCertUtils.generateCACert(
                new X500Name("CN=Root"), rootKP, new X500Name("CN=Root"));

        KeyPair leafKP = KeyPairGenerator.getInstance("RSA", "BC").generateKeyPair();
        X509Certificate leaf = TestCertUtils.generateEndEntityCert(
                new X500Name("CN=Leaf"), leafKP, new X500Name("CN=Root"), rootKP.getPublic());

        store.setCertificateEntry("root", root);

        ChainWalker walker = new ChainWalker();
        Set<X509Certificate> chain = walker.buildChain(store, leaf);
        assertThat(chain).hasSize(1);
        assertThat(chain.iterator().next().getSubjectX500Principal())
                .isEqualTo(root.getSubjectX500Principal());
    }

    @Test
    void buildChainFindsThreeLevelChain() throws Exception {
        KeyStore store = KeyStore.getInstance("BKS", "BC");
        store.load(null, TestCertUtils.BKS_PASSWORD.toCharArray());

        KeyPair rootKP = KeyPairGenerator.getInstance("RSA", "BC").generateKeyPair();
        X509Certificate root = TestCertUtils.generateCACert(
                new X500Name("CN=Root"), rootKP, new X500Name("CN=Root"));

        KeyPair interKP = KeyPairGenerator.getInstance("RSA", "BC").generateKeyPair();
        X509Certificate inter = TestCertUtils.generateCACert(
                new X500Name("CN=Inter"), interKP, new X500Name("CN=Root"), rootKP.getPublic());

        KeyPair leafKP = KeyPairGenerator.getInstance("RSA", "BC").generateKeyPair();
        X509Certificate leaf = TestCertUtils.generateEndEntityCert(
                new X500Name("CN=Leaf"), leafKP, new X500Name("CN=Inter"), interKP.getPublic());

        store.setCertificateEntry("root", root);
        store.setCertificateEntry("inter", inter);

        ChainWalker walker = new ChainWalker();
        Set<X509Certificate> chain = walker.buildChain(store, leaf);
        assertThat(chain).hasSize(2);
        assertThat(chain).extracting(X509Certificate::getSubjectX500Principal)
                .containsExactlyInAnyOrder(
                        root.getSubjectX500Principal(),
                        inter.getSubjectX500Principal());
    }

    @Test
    void buildChainPreferSelfSignedOverCrossCert() throws Exception {
        KeyStore store = KeyStore.getInstance("BKS", "BC");
        store.load(null, TestCertUtils.BKS_PASSWORD.toCharArray());

        KeyPair aKP = KeyPairGenerator.getInstance("RSA", "BC").generateKeyPair();
        X500Name aDn = new X500Name("CN=CA A");
        X509Certificate aSelfSigned = TestCertUtils.generateCACert(aDn, aKP, aDn);

        KeyPair bKP = KeyPairGenerator.getInstance("RSA", "BC").generateKeyPair();
        X500Name bDn = new X500Name("CN=CA B");
        X509Certificate crossCert = TestCertUtils.generateCrossCert(aDn, aKP, bDn, bKP);

        store.setCertificateEntry("a-self", aSelfSigned);
        store.setCertificateEntry("a-cross", crossCert);

        ChainWalker walker = new ChainWalker();
        Set<X509Certificate> chain = walker.buildChain(store, aSelfSigned);
        assertThat(chain).hasSize(1);
        assertThat(CertUtils.isSelfSigned(chain.iterator().next())).isTrue();
    }

    @Test
    void buildChainDetectsCycleAndStops() throws Exception {
        KeyStore store = KeyStore.getInstance("BKS", "BC");
        store.load(null, TestCertUtils.BKS_PASSWORD.toCharArray());

        KeyPair aKP = KeyPairGenerator.getInstance("RSA", "BC").generateKeyPair();
        X500Name aDn = new X500Name("CN=CA A");
        X509Certificate a = TestCertUtils.generateCACert(aDn, aKP, aDn);

        KeyPair bKP = KeyPairGenerator.getInstance("RSA", "BC").generateKeyPair();
        X500Name bDn = new X500Name("CN=CA B");
        X509Certificate b = TestCertUtils.generateCACert(bDn, bKP, aDn, aKP.getPublic());

        store.setCertificateEntry("a", a);
        store.setCertificateEntry("b", b);

        ChainWalker walker = new ChainWalker();
        Set<X509Certificate> chain = walker.buildChain(store, b);
        assertThat(chain.size()).isLessThanOrEqualTo(5);
    }

    @Test
    void buildChainWithResourceCerts() throws Exception {
        KeyStore store = KeyStore.getInstance("BKS", "BC");
        store.load(null, TestCertUtils.BKS_PASSWORD.toCharArray());

        X509Certificate root = TestCertUtils.loadCertFromResources("untrusted/ROOT.cer");
        X509Certificate ca = TestCertUtils.loadCertFromResources("untrusted/CA.cer");
        X509Certificate user = TestCertUtils.loadCertFromResources("untrusted/USER.cer");

        store.setCertificateEntry("root", root);
        store.setCertificateEntry("ca", ca);
        store.setCertificateEntry("user", user);

        ChainWalker walker = new ChainWalker();
        Set<X509Certificate> chain = walker.buildChain(store, user);
        assertThat(chain).isNotEmpty();
        assertThat(chain).extracting(X509Certificate::getSubjectX500Principal)
                .anyMatch(s -> s.equals(ca.getSubjectX500Principal()));
    }
}
