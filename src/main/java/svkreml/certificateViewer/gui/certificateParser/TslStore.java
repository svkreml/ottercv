package svkreml.certificateViewer.gui.certificateParser;

import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Unmarshaller;
import lombok.extern.slf4j.Slf4j;
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
public class TslStore {

    private static final char[] BKS_PASSWORD = "cgvybtunm,ovgcfre".toCharArray();
    private final Set<X509Certificate> caFolderCerts = ConcurrentHashMap.newKeySet();

    public boolean isFromCaFolder(X509Certificate cert) {
        return caFolderCerts.contains(cert);
    }

    public KeyStore loadKeyStore(Localization localization) throws
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

    public Set<X509Certificate> downloadTsl(Localization localization)
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

    private KeyStore convertXmlToBks(Localization localization) throws
            IOException,
            JAXBException,
            KeyStoreException,
            NoSuchProviderException,
            NoSuchAlgorithmException,
            CertificateException {
        log.info("Качаем TSL {}", localization.TSL_LOCATION);
        Set<X509Certificate> list = downloadTsl(localization);
        log.info("TSL downloaded, certs count: {}", list.size());

        list = list.stream().filter(c -> c.getNotAfter().after(new Date())).collect(Collectors.toSet());

        return initTLSStore(localization, list);
    }

    private KeyStore initTLSStore(Localization localization, Set<X509Certificate> list) throws
            KeyStoreException,
            NoSuchProviderException,
            IOException,
            NoSuchAlgorithmException,
            CertificateException {

        KeyStore trusted1 = KeyStore.getInstance("BKS", "BC");

        trusted1.load(null, BKS_PASSWORD);
        int count = 0;
        for (X509Certificate x509Certificate : list) {
            String alias =
                    x509Certificate.getSubjectX500Principal().getName() + "\t"
                            + Hex.toHexString(Objects.requireNonNull(CertUtils.getSubjectKeyIdentifier(x509Certificate)))
                            + "\t" + CertUtils.certFingerprint(x509Certificate);
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

    private void addRootCertsFromCaFolder(KeyStore keyStore, String bksFilePath) {
        caFolderCerts.clear();
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
                byte[] ski = CertUtils.getSubjectKeyIdentifier(cert);
                if (ski == null) {
                    log.warn("Skipping CA certificate {}: no Subject Key Identifier", file.getName());
                    continue;
                }
                String alias = Hex.toHexString(ski) + "\t" + CertUtils.certFingerprint(cert);
                keyStore.setCertificateEntry(alias, cert);
                caFolderCerts.add(cert);
                log.debug("Added root certificate from {}: subject={}, ski={}", file.getName(),
                        cert.getSubjectX500Principal(), Hex.toHexString(ski));
                added++;
            } catch (Exception e) {
                log.error("Failed to load certificate from {}: {}", file.getName(), e.getMessage(), e);
            }
        }
        log.info("Added {} certificates from CA folder", added);
    }
}
