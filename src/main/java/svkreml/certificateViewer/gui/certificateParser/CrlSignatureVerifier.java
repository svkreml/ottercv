package svkreml.certificateViewer.gui.certificateParser;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import svkreml.certificateViewer.gui.api.model.CrlStatus;
import svkreml.certificateViewer.gui.localization.ru.Localization;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

/**
 * Verifies the signature of a CRL using its issuer certificate.
 * <p>
 * Issuer certificates are searched next to the CRL file and in the TSL/CA
 * keystore. When several certificates have the same subject, the authority
 * key identifier is used to narrow the candidates.
 */
@Slf4j
public final class CrlSignatureVerifier {

    private static final Set<String> CERTIFICATE_EXTENSIONS =
            Set.of(".pem", ".cer", ".crt", ".der", ".cert");

    private CrlSignatureVerifier() {
    }

    public static VerificationResult verify(X509CRLHolder crl,
                                            Path sourceFile,
                                            Localization localization) {
        List<X509CertificateHolder> candidates = new ArrayList<>();
        if (sourceFile != null) {
            candidates.addAll(loadCertificatesFromDirectory(sourceFile));
        }
        List<X509CertificateHolder> issuerCandidates = findIssuerCandidates(crl, candidates);
        byte[] authorityKeyIdentifier = getAuthorityKeyIdentifier(crl);
        boolean hasMatchingKeyIdentifier = authorityKeyIdentifier != null
                && issuerCandidates.stream().anyMatch(certificate ->
                Arrays.equals(authorityKeyIdentifier, getSubjectKeyIdentifier(certificate)));
        if (issuerCandidates.isEmpty() || (authorityKeyIdentifier != null && !hasMatchingKeyIdentifier)) {
            candidates.addAll(loadCertificatesFromTsl(localization));
            issuerCandidates = findIssuerCandidates(crl, candidates);
        }
        if (issuerCandidates.isEmpty()) {
            return new VerificationResult(
                    CrlStatus.ISSUER_NOT_FOUND,
                    List.of(localization.CRL_ISSUER_NOT_FOUND));
        }

        List<String> errors = new ArrayList<>();
        for (X509CertificateHolder issuer : issuerCandidates) {
            try {
                boolean valid = crl.isSignatureValid(
                        new JcaContentVerifierProviderBuilder()
                                .setProvider("BC")
                                .build(issuer));
                if (valid) {
                    List<String> details = new ArrayList<>();
                    details.add(localization.CRL_SIGNATURE_VALID);
                    details.add(localization.CRL_ISSUER_CERTIFICATE +
                            CertificateParser.parseX500ToTextArea(
                                    CertificateParser.x500NameToMap(issuer.getSubject())));
                    CrlStatus status = resolveTimeStatus(crl, localization, details);
                    return new VerificationResult(status, details);
                }
                errors.add(localization.CRL_SIGNATURE_ERROR +
                        CertificateParser.parseX500ToTextArea(
                                CertificateParser.x500NameToMap(issuer.getSubject())));
            } catch (Exception e) {
                log.debug("CRL signature verification failed with issuer {}",
                        issuer.getSubject(), e);
                errors.add(localization.CRL_SIGNATURE_ERROR + e.getMessage());
            }
        }

        List<String> details = new ArrayList<>();
        details.add(localization.CRL_SIGNATURE_INVALID);
        details.addAll(errors);
        return new VerificationResult(CrlStatus.SIGNATURE_INVALID, details);
    }

    private static CrlStatus resolveTimeStatus(X509CRLHolder crl,
                                               Localization localization,
                                               List<String> details) {
        Date now = new Date();
        if (crl.getThisUpdate() != null && now.before(crl.getThisUpdate())) {
            details.add(localization.CRL_NOT_YET_VALID +
                    localization.formatDate(crl.getThisUpdate()));
            return CrlStatus.NOT_YET_VALID;
        }
        if (crl.getNextUpdate() != null && now.after(crl.getNextUpdate())) {
            details.add(localization.CRL_EXPIRED +
                    localization.formatDate(crl.getNextUpdate()));
            return CrlStatus.EXPIRED;
        }
        return CrlStatus.VALID;
    }

    private static List<X509CertificateHolder> findIssuerCandidates(X509CRLHolder crl,
                                                                    List<X509CertificateHolder> certificates) {
        X500Name crlIssuer = crl.getIssuer();
        byte[] authorityKeyIdentifier = getAuthorityKeyIdentifier(crl);

        Map<String, X509CertificateHolder> candidates = new LinkedHashMap<>();
        for (X509CertificateHolder certificate : certificates) {
            if (certificate.getSubject().equals(crlIssuer)) {
                addCandidate(candidates, certificate);
            }
        }
        if (authorityKeyIdentifier != null) {
            for (X509CertificateHolder certificate : certificates) {
                if (Arrays.equals(authorityKeyIdentifier, getSubjectKeyIdentifier(certificate))) {
                    addCandidate(candidates, certificate);
                }
            }
        }
        return new ArrayList<>(candidates.values());
    }

    private static void addCandidate(Map<String, X509CertificateHolder> candidates,
                                     X509CertificateHolder certificate) {
        try {
            String key = java.util.Base64.getEncoder().encodeToString(certificate.getEncoded());
            candidates.putIfAbsent(key, certificate);
        } catch (Exception e) {
            log.debug("Failed to deduplicate issuer candidate", e);
        }
    }

    private static byte[] getAuthorityKeyIdentifier(X509CRLHolder crl) {
        Extension extension = crl.getExtension(Extension.authorityKeyIdentifier);
        if (extension == null) {
            return null;
        }
        try {
            return AuthorityKeyIdentifier.getInstance(extension.getParsedValue()).getKeyIdentifier();
        } catch (Exception e) {
            log.debug("Failed to parse CRL authority key identifier", e);
            return null;
        }
    }

    private static byte[] getSubjectKeyIdentifier(X509CertificateHolder certificate) {
        Extension extension = certificate.getExtension(Extension.subjectKeyIdentifier);
        if (extension == null) {
            return null;
        }
        try {
            return SubjectKeyIdentifier.getInstance(
                    ASN1OctetString.getInstance(extension.getExtnValue()).getOctets()).getKeyIdentifier();
        } catch (Exception e) {
            log.debug("Failed to parse certificate subject key identifier", e);
            return null;
        }
    }

    private static List<X509CertificateHolder> loadCertificatesFromDirectory(Path sourceFile) {
        List<X509CertificateHolder> certificates = new ArrayList<>();
        Path absoluteSource = sourceFile.toAbsolutePath();
        Path directory = absoluteSource.getParent();
        if (directory == null || !Files.isDirectory(directory)) {
            return certificates;
        }
        try (Stream<Path> files = Files.list(directory)) {
            files.filter(Files::isRegularFile)
                    .filter(path -> !path.toAbsolutePath().equals(absoluteSource))
                    .filter(CrlSignatureVerifier::isCertificateFile)
                    .forEach(path -> {
                        try {
                            certificates.addAll(InputLoader.loadCertificates(Files.readAllBytes(path)));
                        } catch (Exception e) {
                            log.debug("Skipping non-certificate file {}: {}", path, e.getMessage());
                        }
                    });
        } catch (Exception e) {
            log.warn("Failed to list directory {} for issuer certificates: {}",
                    directory, e.getMessage());
        }
        return certificates;
    }

    private static boolean isCertificateFile(Path path) {
        String name = path.getFileName().toString().toLowerCase(Locale.ROOT);
        return CERTIFICATE_EXTENSIONS.stream().anyMatch(name::endsWith);
    }

    private static List<X509CertificateHolder> loadCertificatesFromTsl(Localization localization) {
        List<X509CertificateHolder> certificates = new ArrayList<>();
        try {
            KeyStore keyStore = new TslStore().loadKeyStore(localization);
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                Certificate certificate = keyStore.getCertificate(alias);
                if (certificate instanceof X509Certificate x509Certificate) {
                    certificates.add(new JcaX509CertificateHolder(x509Certificate));
                }
            }
        } catch (Exception e) {
            log.debug("Failed to load certificates from TSL for CRL verification: {}", e.getMessage());
        }
        return certificates;
    }

    public record VerificationResult(CrlStatus status, List<String> details) {
    }
}
