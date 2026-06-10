package svkreml.certificateViewer.gui.certificateParser;


import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Unmarshaller;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.encoders.Hex;
import svkreml.certificateViewer.gui.localization.ru.Localization;
import svkreml.tsl.tsl.ACA;
import svkreml.tsl.tsl.CertData;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.URI;
import java.net.URL;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

@Slf4j
public class TrustChainBuilder {

    public static Set<X509Certificate> fullInit(Localization localization) throws
            NoSuchProviderException,
            KeyStoreException,
            CertificateException,
            IOException,
            NoSuchAlgorithmException,
            JAXBException,
            UnrecoverableEntryException {
        HashSet<X509Certificate> set = new HashSet<>();
        KeyStore trusted = getKeyStore(localization);
        Enumeration<String> aliases = trusted.aliases();
        while (aliases.hasMoreElements()) {
            set.add(KeyParser.loadCertificate(trusted.getCertificate(aliases.nextElement()).getEncoded()));
        }
        return set;
    }

    public static Set<X509Certificate> smallInit(Localization localization, X509CertificateHolder x509Certificate)
            throws
            NoSuchProviderException,
            KeyStoreException,
            CertificateException,
            IOException,
            NoSuchAlgorithmException,
            JAXBException,
            UnrecoverableEntryException {
        return smallInit(localization, KeyParser.loadCertificate(x509Certificate.getEncoded()));
    }


    public static Set<X509Certificate> smallInit(Localization localization, X509Certificate x509Certificate) throws
            NoSuchProviderException,
            KeyStoreException,
            CertificateException,
            IOException,
            NoSuchAlgorithmException,
            JAXBException,
            UnrecoverableEntryException {
        LinkedHashSet<X509Certificate> set = new LinkedHashSet<>();
        KeyStore trusted = getKeyStore(localization);
        final byte[] authKeyIdentifier2 = getAuthKeyIdentifier(x509Certificate);
        if (authKeyIdentifier2 == null) {
            final byte[] subKeyIdentifier = getSubKeyIdentifier(x509Certificate);
            if (subKeyIdentifier != null) {
                java.security.cert.Certificate certificate = trusted.getCertificate(
                        CustomBCStyle.INSTANCE.toString(X500Name.getInstance(x509Certificate.getIssuerX500Principal()
                                .getEncoded()))
                                + " " + Hex.toHexString((Objects.requireNonNull(subKeyIdentifier))));
                if (certificate == null) return set;
                X509Certificate chainCert = KeyParser.loadCertificate(certificate.getEncoded());
                if (chainCert == null) return set;
                set.add(chainCert);
            }
            return set;
        }
        String authKeyIdentifier = Hex.toHexString((Objects.requireNonNull(authKeyIdentifier2)));
        while (true) {
            java.security.cert.Certificate
                    certificate =
                    trusted.getCertificate(CustomBCStyle.INSTANCE.toString(X500Name.getInstance(x509Certificate.getIssuerX500Principal()
                            .getEncoded()))
                            + " " + authKeyIdentifier);
            if (certificate == null) break;
            X509Certificate chainCert = KeyParser.loadCertificate(certificate.getEncoded());
            if (chainCert == null) break;
            set.add(chainCert);
            byte[] authKeyIdentifier1 = getAuthKeyIdentifier(chainCert);
            if (authKeyIdentifier1 == null)
                break;
            String s = Hex.toHexString(authKeyIdentifier1);
            if (s.equals(authKeyIdentifier))
                break;
            authKeyIdentifier = s;
        }
        return set;
    }

    private static KeyStore getKeyStore(Localization localization) throws
            KeyStoreException,
            NoSuchProviderException,
            IOException,
            NoSuchAlgorithmException,
            CertificateException,
            UnrecoverableEntryException,
            JAXBException {
        KeyStore trusted = KeyStore.getInstance("BKS", "BC");
        String tsl_location_bks = localization.TSL_LOCATION_BKS;
        File file = new File(tsl_location_bks);
        if (file.exists()) {
            trusted.load(new FileInputStream(tsl_location_bks), "cgvybtunm,ovgcfre".toCharArray());
            addRootCertsFromCaFolder(trusted, tsl_location_bks);

            Date createDate = new Date(Long.parseLong(
                    new String(((KeyStore.SecretKeyEntry) trusted.getEntry("info",
                            new KeyStore.PasswordProtection("creation date".toCharArray()))).getSecretKey()
                            .getEncoded()))
            );
            Calendar cal = Calendar.getInstance();
            cal.add(Calendar.DATE, -30);
            if (createDate.before(cal.getTime())) {
                log.info("Tsl уже старый, обновим");
                return convertXmlToBks(localization);
            }
            log.info("Tsl ещё не старый, используем");
            return trusted;
        }
        log.info("Tsl ещё не создан, создаём");
        log.debug("Создаём папки {}", file.getAbsoluteFile().getParentFile().mkdirs());
        return convertXmlToBks(localization);
    }

    private static KeyStore convertXmlToBks(Localization localization) throws
            IOException,
            JAXBException,
            KeyStoreException,
            NoSuchProviderException,
            NoSuchAlgorithmException,
            CertificateException {
        log.info("Качаем TSL {}", localization.TSL_LOCATION);
        Set<X509Certificate> list = gostTlsStore(localization);
        return initTLSStore(localization, list);
    }

    private static KeyStore initTLSStore(Localization localization, Set<X509Certificate> list) throws
            KeyStoreException,
            NoSuchProviderException,
            IOException,
            NoSuchAlgorithmException,
            CertificateException {

        KeyStore trusted1 = KeyStore.getInstance("BKS", "BC");

        trusted1.load(null, "cgvybtunm,ovgcfre".toCharArray());
        for (X509Certificate x509Certificate : list) {
            trusted1.setCertificateEntry(CustomBCStyle.INSTANCE.toString(X500Name.getInstance(x509Certificate.getIssuerX500Principal()
                            .getEncoded()))
                            + " "
                            + Hex.toHexString(Objects.requireNonNull(getSubjectKeyIdentifier(x509Certificate))),
                    x509Certificate);
        }
        addRootCertsFromCaFolder(trusted1, localization.TSL_LOCATION_BKS);
        byte[] keyBytes = ("" + new Date().getTime()).getBytes();
        SecretKey a = new SecretKeySpec(keyBytes, "AES");
        Set<KeyStore.Entry.Attribute> b = new HashSet<>();
        KeyStore.SecretKeyEntry entry = new KeyStore.SecretKeyEntry(a, b);

        KeyStore.ProtectionParameter params = new KeyStore.PasswordProtection("creation date".toCharArray());
        trusted1.setEntry("info", entry, params);
        trusted1.store(new FileOutputStream(localization.TSL_LOCATION_BKS), "cgvybtunm,ovgcfre".toCharArray());
        return trusted1;
    }

    public static Set<X509Certificate> gostTlsStore(Localization localization)
            throws IOException, JAXBException, CertificateException {
        URL url = URI.create(localization.TSL_LOCATION).toURL();
        try (InputStream tslStream = url.openStream()) {
            Set<X509Certificate> list = new HashSet<>();
            JAXBContext jaxbContext = JAXBContext.newInstance(ACA.class);
            Unmarshaller jaxbUnmarshaller = jaxbContext.createUnmarshaller();
            ACA tsl = (ACA) jaxbUnmarshaller.unmarshal(tslStream);
            for (ACA.CA CA : tsl.getCA()) {
                for (ACA.CA.PAKs.PAK PAK : CA.getPAKs().getPAK()) {
                    for (ACA.CA.PAKs.PAK.Keys.Key key : PAK.getKeys().getKey()) {
                        for (CertData certData : key.getCerts().getCertData()) {
                            list.add(KeyParser.loadCertificate(certData.getRawCert()));
                        }
                    }
                }
            }
            return list;
        }
    }

    private static void addRootCertsFromCaFolder(KeyStore keyStore, String bksFilePath) {
        File caDir = new File(new File(bksFilePath).getParentFile(), "ca");
        if (!caDir.exists() || !caDir.isDirectory()) {
            return;
        }
        File[] files = caDir.listFiles();
        if (files == null) {
            return;
        }
        for (File file : files) {
            if (!file.isFile()) continue;
            try {
                X509Certificate cert = KeyParser.loadCertificate(Files.readAllBytes(file.toPath()));
                byte[] ski = getSubjectKeyIdentifier(cert);
                if (ski == null) {
                    log.debug("Skipping certificate {}: no Subject Key Identifier", file.getName());
                    continue;
                }
                String
                        alias =
                        CustomBCStyle.INSTANCE.toString(X500Name.getInstance(cert.getIssuerX500Principal()
                                .getEncoded()))
                                + " " + Hex.toHexString(ski);
                keyStore.setCertificateEntry(alias, cert);
                log.debug("Added root certificate from {}", file.getName());
            } catch (Exception e) {
                log.error("Failed to load certificate from {}: {}", file.getName(), e.getMessage(), e);
            }
        }
    }

    private static byte[] getSubjectKeyIdentifier(X509Certificate certificate) {
        try {
            byte[] value = certificate.getExtensionValue(Extension.subjectKeyIdentifier.getId());
            return SubjectKeyIdentifier.getInstance(Arrays.copyOfRange(value, 2, value.length)).getKeyIdentifier();
        } catch (Exception e) {
            return null;
        }
    }


    private static byte[] getAuthKeyIdentifier(X509Certificate certificate) {
        try {
            byte[] value = certificate.getExtensionValue("2.5.29.35");
            if (value.length < 28)
                return AuthorityKeyIdentifier.getInstance(Arrays.copyOfRange(value, 2, value.length))
                        .getKeyIdentifier();
            else
                return AuthorityKeyIdentifier.getInstance(Arrays.copyOfRange(value, 4, value.length))
                        .getKeyIdentifier();
        } catch (Exception e) {
            return null;
        }
    }

    private static byte[] getSubKeyIdentifier(X509Certificate certificate) {
        try {
            byte[] value = certificate.getExtensionValue("2.5.29.14");
            if (value.length < 28)
                return SubjectKeyIdentifier.getInstance(Arrays.copyOfRange(value, 2, value.length)).getKeyIdentifier();
            else
                return SubjectKeyIdentifier.getInstance(Arrays.copyOfRange(value, 4, value.length)).getKeyIdentifier();
        } catch (Exception e) {
            return null;
        }
    }

}
