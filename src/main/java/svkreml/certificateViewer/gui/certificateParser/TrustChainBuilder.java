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
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Slf4j
public class TrustChainBuilder {
    private static final char[] BKS_PASSWORD = "cgvybtunm,ovgcfre".toCharArray();
    private static final Set<X509Certificate> CA_FOLDER_CERTS = ConcurrentHashMap.newKeySet();

    public static boolean isFromCaFolder(X509Certificate cert) {
        return CA_FOLDER_CERTS.contains(cert);
    }

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
        log.debug("smallInit for cert subject={}", x509Certificate.getSubjectX500Principal());

        final byte[] authKeyIdentifierRaw = getAuthKeyIdentifier(x509Certificate);
        final byte[] subKeyIdentifier = getSubKeyIdentifier(x509Certificate);
        log.debug("Leaf cert AKI={}, SKI={}",
                authKeyIdentifierRaw != null ? Hex.toHexString(authKeyIdentifierRaw) : "null",
                subKeyIdentifier != null ? Hex.toHexString(subKeyIdentifier) : "null");

        if (authKeyIdentifierRaw == null) {
            if (subKeyIdentifier != null) {
                String lookupAlias = Hex.toHexString(subKeyIdentifier);
                log.debug("No AKI, looking up by subject+SKI: {}", lookupAlias);
                java.security.cert.Certificate certificate = trusted.getCertificate(lookupAlias);
                if (certificate == null) {
                    log.debug("Not found in keystore by subject+SKI");
                    return set;
                }
                X509Certificate chainCert = KeyParser.loadCertificate(certificate.getEncoded());
                if (chainCert == null) return set;
                set.add(chainCert);
                log.debug("Found chain cert: {}", chainCert.getSubjectX500Principal());
            }
            return set;
        }

        String authKeyIdentifier = Hex.toHexString(authKeyIdentifierRaw);
        int hop = 0;
        while (true) {
            hop++;
            String lookupAlias = authKeyIdentifier;
            log.debug("Hop {}: looking up issuer by AKI={}, alias={}", hop, authKeyIdentifier, lookupAlias);

            java.security.cert.Certificate certificate = trusted.getCertificate(authKeyIdentifier);
            if (certificate == null) {
                log.debug("Hop {}: issuer not found in keystore, chain ends", hop);
                break;
            }
            X509Certificate chainCert = KeyParser.loadCertificate(certificate.getEncoded());
            if (chainCert == null) {
                log.debug("Hop {}: failed to parse issuer cert", hop);
                break;
            }
            set.add(chainCert);
            log.debug("Hop {}: found issuer: subject={}", hop, chainCert.getSubjectX500Principal());

            byte[] authKeyIdentifier1 = getAuthKeyIdentifier(chainCert);
            if (authKeyIdentifier1 == null) {
                log.debug("Hop {}: issuer has no AKI, chain ends", hop);
                break;
            }
            String nextAki = Hex.toHexString(authKeyIdentifier1);
            log.debug("Hop {}: issuer AKI={}", hop, nextAki);
            if (nextAki.equals(authKeyIdentifier)) {
                log.debug("Hop {}: AKI loop detected, chain ends", hop);
                break;
            }
            authKeyIdentifier = nextAki;
            x509Certificate = chainCert;
        }
        log.info("smallInit completed, chain size: {}", set.size());
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
        log.debug("BKS path: {}", tsl_location_bks);
        if (file.exists()) {
            log.debug("BKS exists, loading...");
            trusted.load(new FileInputStream(tsl_location_bks), BKS_PASSWORD);
            addRootCertsFromCaFolder(trusted, tsl_location_bks);

            Date createDate = new Date(Long.parseLong(
                    new String(((KeyStore.SecretKeyEntry) trusted.getEntry("info",
                            new KeyStore.PasswordProtection("creation date".toCharArray()))).getSecretKey()
                            .getEncoded()))
            );
            Calendar cal = Calendar.getInstance();
            cal.add(Calendar.DATE, -30);
            log.debug("BKS creation date: {}, threshold: {}", createDate, cal.getTime());
            if (createDate.before(cal.getTime())) {
                log.info("Tsl уже старый ({}), обновим", createDate);
                return convertXmlToBks(localization);
            }
            log.info("Tsl ещё не старый ({}), используем существующий", createDate);
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
        log.info("TSL downloaded, certs count: {}", list.size());

        list = list.stream().filter(c -> c.getNotAfter().after(new Date())).collect(Collectors.toSet());

        return initTLSStore(localization, list);
    }

    private static KeyStore initTLSStore(Localization localization, Set<X509Certificate> list) throws
            KeyStoreException,
            NoSuchProviderException,
            IOException,
            NoSuchAlgorithmException,
            CertificateException {

        KeyStore trusted1 = KeyStore.getInstance("BKS", "BC");

        trusted1.load(null, BKS_PASSWORD);
        int count = 0;
        for (X509Certificate x509Certificate : list) {
            String alias = Hex.toHexString(Objects.requireNonNull(getSubjectKeyIdentifier(x509Certificate)));
            trusted1.setCertificateEntry(alias, x509Certificate);
            log.debug("Stored TSL cert #{}: alias={}, subject={}",
                    ++count,
                    alias,
                    x509Certificate.getSubjectX500Principal());
        }
        addRootCertsFromCaFolder(trusted1, localization.TSL_LOCATION_BKS);
        byte[] keyBytes = ("" + new Date().getTime()).getBytes();
        SecretKey a = new SecretKeySpec(keyBytes, "AES");
        Set<KeyStore.Entry.Attribute> b = new HashSet<>();
        KeyStore.SecretKeyEntry entry = new KeyStore.SecretKeyEntry(a, b);

        KeyStore.ProtectionParameter params = new KeyStore.PasswordProtection("creation date".toCharArray());
        trusted1.setEntry("info", entry, params);
        trusted1.store(new FileOutputStream(localization.TSL_LOCATION_BKS), BKS_PASSWORD);
        log.info("BKS saved to {}, total certs: {}", localization.TSL_LOCATION_BKS, count);
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
        CA_FOLDER_CERTS.clear();
        File caDir = new File(new File(bksFilePath).getParentFile(), "ca");
        log.debug("CA folder path: {}", caDir.getAbsolutePath());
        if (!caDir.exists() || !caDir.isDirectory()) {
            log.debug("CA folder does not exist or is not a directory");
            return;
        }
        File[] files = caDir.listFiles();
        if (files == null) {
            log.debug("CA folder is empty or cannot be listed");
            return;
        }
        log.debug("CA folder contains {} files", files.length);
        int added = 0;
        for (File file : files) {
            if (!file.isFile()) continue;
            try {
                X509Certificate cert = KeyParser.loadCertificate(Files.readAllBytes(file.toPath()));
                byte[] ski = getSubjectKeyIdentifier(cert);
                if (ski == null) {
                    log.warn("Skipping CA certificate {}: no Subject Key Identifier", file.getName());
                    continue;
                }
                String
                        alias =
                        CustomBCStyle.INSTANCE.toString(X500Name.getInstance(cert.getSubjectX500Principal()
                                .getEncoded()))
                                + " " + Hex.toHexString(ski);
                keyStore.setCertificateEntry(alias, cert);
                CA_FOLDER_CERTS.add(cert);
                log.debug("Added root certificate from {}: subject={}, ski={}", file.getName(),
                        cert.getSubjectX500Principal(), Hex.toHexString(ski));
                added++;
            } catch (Exception e) {
                log.error("Failed to load certificate from {}: {}", file.getName(), e.getMessage(), e);
            }
        }
        log.info("Added {} certificates from CA folder", added);
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
            return AuthorityKeyIdentifier.getInstance(
                    org.bouncycastle.asn1.ASN1OctetString.getInstance(value).getOctets()
            ).getKeyIdentifier();
        } catch (Exception e) {
            return null;
        }
    }

    private static byte[] getSubKeyIdentifier(X509Certificate certificate) {
        try {
            byte[] value = certificate.getExtensionValue("2.5.29.14");
            return SubjectKeyIdentifier.getInstance(
                    org.bouncycastle.asn1.ASN1OctetString.getInstance(value).getOctets()
            ).getKeyIdentifier();
        } catch (Exception e) {
            return null;
        }
    }

}
