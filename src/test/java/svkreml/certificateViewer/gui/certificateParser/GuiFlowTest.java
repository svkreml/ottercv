package svkreml.certificateViewer.gui.certificateParser;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.nio.file.Files;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import svkreml.certificateViewer.gui.certificateParser.chainBuilder.CertificateVerifier;

import static org.assertj.core.api.Assertions.assertThat;

class GuiFlowTest {

    @Test
    void testGuiFlowForSelfSignedCert() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        
        byte[] certBytes = Files.readAllBytes(new File("src/test/resources/2F0CB09BE3550EF17EC4F29C90ABD18BFCAAD63A.cer").toPath());
        
        // GUI way - using X509CertificateHolder
        X509CertificateHolder holder = new X509CertificateHolder(certBytes);
        System.out.println("=== GUI way (X509CertificateHolder) ===");
        System.out.println("Subject: " + holder.getSubject());
        System.out.println("Issuer: " + holder.getIssuer());
        
        // Convert to Java X509Certificate for verification (like CertificateVerifier does)
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(holder.getEncoded()));
        
        System.out.println("\n=== Java X509Certificate ===");
        System.out.println("Subject: " + cert.getSubjectX500Principal());
        System.out.println("Issuer: " + cert.getIssuerX500Principal());
        System.out.println("Equals: " + cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal()));
        
        // Test verify
        try {
            cert.verify(cert.getPublicKey());
            System.out.println("Self-verify: SUCCESS");
        } catch (Exception e) {
            System.out.println("Self-verify: FAILED - " + e.getMessage());
        }
        
        // Test isSelfSigned
        boolean selfSigned = CertificateVerifier.isSelfSigned(cert);
        System.out.println("isSelfSigned: " + selfSigned);
        
        assertThat(selfSigned).isTrue();
    }
}
