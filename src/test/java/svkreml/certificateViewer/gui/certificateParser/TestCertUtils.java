package svkreml.certificateViewer.gui.certificateParser;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Hex;

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
import java.util.Date;
import java.util.Set;

public final class TestCertUtils {

    public static final String BKS_PASSWORD = "cgvybtunm,ovgcfre";

    private TestCertUtils() {
    }

    public static void ensureBcProvider() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static X509Certificate loadCertFromResources(String fileName) throws Exception {
        byte[] certBytes = Files.readAllBytes(new File("src/test/resources/" + fileName).toPath());
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(certBytes));
    }

    public static X509CertificateHolder loadHolderFromResources(String fileName) throws Exception {
        X509Certificate cert = loadCertFromResources(fileName);
        return new X509CertificateHolder(cert.getEncoded());
    }

    public static byte[] getSki(X509Certificate cert) throws Exception {
        byte[] value = cert.getExtensionValue(Extension.subjectKeyIdentifier.getId());
        if (value == null) return null;
        return SubjectKeyIdentifier.getInstance(
                org.bouncycastle.asn1.ASN1OctetString.getInstance(value).getOctets()
        ).getKeyIdentifier();
    }

    public static X509Certificate generateCACert(X500Name subject, KeyPair keyPair,
                                                   X500Name issuer) throws Exception {
        return generateCACert(subject, keyPair, issuer, null);
    }

    public static X509Certificate generateCACert(X500Name subject, KeyPair keyPair,
                                                   X500Name issuer,
                                                   PublicKey issuerPublicKey) throws Exception {
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

    public static X509Certificate generateEndEntityCert(X500Name subject, KeyPair keyPair,
                                                         X500Name issuer,
                                                         PublicKey issuerPublicKey) throws Exception {
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

    public static X509Certificate generateCrossCert(X500Name subject, KeyPair subjectKeyPair,
                                                     X500Name issuer,
                                                     KeyPair issuerKeyPair) throws Exception {
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

    public static X509Certificate convertToX509Cert(X509CertificateHolder holder)
            throws CertificateException, IOException {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) factory.generateCertificate(
                new ByteArrayInputStream(holder.getEncoded()));
    }

    public static String createTempBks(X509Certificate... certs) throws Exception {
        KeyStore bks = KeyStore.getInstance("BKS", "BC");
        bks.load(null, BKS_PASSWORD.toCharArray());

        for (X509Certificate cert : certs) {
            byte[] ski = getSki(cert);
            if (ski != null) {
                bks.setCertificateEntry(Hex.toHexString(ski), cert);
            }
        }

        storeBksInfo(bks);

        File tempBks = File.createTempFile("test-", ".bks");
        tempBks.deleteOnExit();
        bks.store(new FileOutputStream(tempBks), BKS_PASSWORD.toCharArray());
        return tempBks.getAbsolutePath();
    }

    public static String createTempBksWithHolder(X509CertificateHolder holder) throws Exception {
        X509Certificate cert = convertToX509Cert(holder);
        return createTempBks(cert);
    }

    public static String createTempBksWithHolders(X509CertificateHolder... holders) throws Exception {
        KeyStore bks = KeyStore.getInstance("BKS", "BC");
        bks.load(null, BKS_PASSWORD.toCharArray());

        for (X509CertificateHolder holder : holders) {
            X509Certificate cert = convertToX509Cert(holder);
            byte[] ski = getSki(cert);
            if (ski != null) {
                bks.setCertificateEntry(Hex.toHexString(ski), cert);
            }
        }

        storeBksInfo(bks);

        File tempBks = File.createTempFile("test-multi-", ".bks");
        tempBks.deleteOnExit();
        bks.store(new FileOutputStream(tempBks), BKS_PASSWORD.toCharArray());
        return tempBks.getAbsolutePath();
    }

    public static String createTempBksWithDuplicateAlias(X509Certificate cert1,
                                                          String alias1,
                                                          X509Certificate cert2,
                                                          String alias2) throws Exception {
        KeyStore bks = KeyStore.getInstance("BKS", "BC");
        bks.load(null, BKS_PASSWORD.toCharArray());

        bks.setCertificateEntry(alias1, cert1);
        bks.setCertificateEntry(alias2, cert2);

        storeBksInfo(bks);

        File tempBks = File.createTempFile("test-dup-", ".bks");
        tempBks.deleteOnExit();
        bks.store(new FileOutputStream(tempBks), BKS_PASSWORD.toCharArray());
        return tempBks.getAbsolutePath();
    }

    private static void storeBksInfo(KeyStore bks) throws Exception {
        byte[] keyBytes = ("" + System.currentTimeMillis()).getBytes();
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
        bks.setEntry("info", new KeyStore.SecretKeyEntry(secretKey),
                new KeyStore.PasswordProtection("creation date".toCharArray()));
    }
}
