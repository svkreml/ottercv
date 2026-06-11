package svkreml.certificateViewer.gui.certificateParser;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.encoders.Hex;
import svkreml.certificateViewer.gui.localization.ru.Localization;
import svkreml.tsl.tsl.ACA;

import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Unmarshaller;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.URI;
import java.net.URL;
import java.nio.file.Files;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * Manages the Trusted Service List (TSL) keystore and local CA folder.
 * <p>
 * Responsibilities:
 * <ul>
 *   <li>Download TSL XML and convert to BKS keystore</li>
 *   <li>Cache certificates in memory and on disk</li>
 *   <li>Load additional root certificates from a local {@code ca/} folder</li>
 *   <li>Detect stale BKS files (older than 30 days) and refresh automatically</li>
 * </ul>
 *
 * <h3>BKS format</h3>
 * Certificates are stored in a BouncyCastle KeyStore (BKS) with aliases
 * encoded as {@code <subject>\t<SKI hex>\t<fingerprint>}.
 */
@Slf4j
public class TslStore {

    private static final int STALE_DAYS_THRESHOLD = 30;

    private static final char[] BKS_PASSWORD = "cgvybtunm,ovgcfre".toCharArray();
    private final Set<X509Certificate> caFolderCerts = ConcurrentHashMap.newKeySet();

    /**
     * Checks whether the given certificate was loaded from the local CA folder.
     *
     * @param cert certificate to check
     * @return {@code true} if the cert is in the CA folder set
     */
    public boolean isFromCaFolder(X509Certificate cert) {
        return caFolderCerts.contains(cert);
    }

    /**
     * Loads the BKS keystore from disk, refreshing if stale (>30 days old).
     * If the file doesn't exist, downloads the TSL and creates it.
     *
     * @param localization application localization (provides BKS file path)
     * @return loaded or freshly-created keystore
     * @throws Exception on I/O or crypto errors
     */
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
            try (var fis = new FileInputStream(tsl_location_bks)) {
                trusted.load(fis, BKS_PASSWORD);
            }
            addRootCertsFromCaFolder(trusted, tsl_location_bks);

            var createDate = Instant.ofEpochMilli(Long.parseLong(
                    new String(((KeyStore.SecretKeyEntry) trusted.getEntry("info",
                            new KeyStore.PasswordProtection("creation date".toCharArray()))).getSecretKey()
                            .getEncoded()))
            );
            var threshold = Instant.now().minus(STALE_DAYS_THRESHOLD, ChronoUnit.DAYS);
            log.debug("BKS creation date: {}, threshold: {}", createDate, threshold);
            if (createDate.isBefore(threshold)) {
                log.info("TSL is stale ({}), refreshing", createDate);
                return convertXmlToBks(localization);
            }
            log.info("TSL is up-to-date ({}), using existing", createDate);
            return trusted;
        }
        log.info("TSL not found, creating");
        log.debug("Creating directories {}", file.getAbsoluteFile().getParentFile().mkdirs());
        return convertXmlToBks(localization);
    }

    /**
     * Downloads the TSL XML and parses all certificates from it.
     *
     * @param localization application localization (provides TSL URL)
     * @return set of unexpired certificates from the TSL
     * @throws IOException on network errors
     * @throws JAXBException on XML parse errors
     * @throws CertificateException on certificate parse errors
     */
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
                        for (svkreml.tsl.tsl.CertData certData : key.getCerts().getCertData()) {
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
        log.info("Downloading TSL from {}", localization.TSL_LOCATION);
        Set<X509Certificate> list = downloadTsl(localization);
        log.info("TSL downloaded, certs count: {}", list.size());

        list = list.stream().filter(c -> c.getNotAfter().toInstant().isAfter(Instant.now())).collect(Collectors.toSet());

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
        byte[] keyBytes = ("" + Instant.now().toEpochMilli()).getBytes();
        SecretKey creationTimestamp = new SecretKeySpec(keyBytes, "AES");
        Set<KeyStore.Entry.Attribute> attributes = new HashSet<>();
        KeyStore.SecretKeyEntry entry = new KeyStore.SecretKeyEntry(creationTimestamp, attributes);

        KeyStore.ProtectionParameter params = new KeyStore.PasswordProtection("creation date".toCharArray());
        trusted1.setEntry("info", entry, params);
        try (var fos = new FileOutputStream(localization.TSL_LOCATION_BKS)) {
            trusted1.store(fos, BKS_PASSWORD);
        }
        log.info("BKS saved to {}, total certs: {}", localization.TSL_LOCATION_BKS, count);
        return trusted1;
    }

    /**
     * Loads root certificates from a local {@code ca/} folder next to the BKS file
     * and adds them to both the keystore and the in-memory set.
     *
     * @param keyStore   BKS keystore to add certificates to
     * @param bksFilePath path to the BKS file (parent directory is used to find {@code ca/})
     */
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
