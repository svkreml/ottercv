package svkreml.certificateViewer.gui.certificateParser;

import lombok.extern.slf4j.Slf4j;
import svkreml.certificateViewer.gui.localization.ru.Localization;

import java.security.KeyStore;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

/**
 * Unified API for certificate chain building and PKIX validation.
 * <p>
 * Combines {@link ChainWalker} (chain discovery via AKI/SKI matching in a keystore)
 * with {@link CertificateVerifier} (PKIX path building and signature verification).
 * Also manages the TSL trust store via {@link TslStore}.
 *
 * <h3>Usage</h3>
 * <pre>{@code
 * var validator = new CertificateChainValidator();
 * var result = validator.validate(localization, cert);
 * if (result.isSuccess()) {
 *     log.info("Trusted via {}", result.trustSource());
 * }
 * }</pre>
 */
@Slf4j
public class CertificateChainValidator {

    private final TslStore tslStore = new TslStore();
    private final ChainWalker chainWalker = new ChainWalker();

    /**
     * Validates a certificate by building its chain and verifying PKIX constraints.
     *
     * @param localization application localization (provides TSL/BKS paths)
     * @param cert         certificate to validate
     * @return {@link ValidationResult} with chain, PKIX result, trust source, and any error
     */
    public ValidationResult validate(Localization localization, X509Certificate cert) {
        try {
            log.debug("Validating cert subject={}", cert.getSubjectX500Principal());
            KeyStore keystore = tslStore.loadKeyStore(localization);
            Set<X509Certificate> chain = chainWalker.buildChain(keystore, cert);

            if (chain.isEmpty()) {
                log.warn("No chain found for cert subject={}", cert.getSubjectX500Principal());
                return ValidationResult.empty(cert);
            }

            CertificateVerifier verifier = new CertificateVerifier(chain);
            PKIXCertPathBuilderResult pkixResult = verifier.verifyCertificate(cert);
            TrustSource trustSource = determineTrustSource(pkixResult);

            log.info("Validation succeeded for cert subject={}, trustSource={}, chainSize={}",
                    cert.getSubjectX500Principal(), trustSource, chain.size());

            return new ValidationResult(pkixResult, chain, trustSource, null);
        } catch (Exception e) {
            log.error("Validation failed for cert subject={}: {}",
                    cert.getSubjectX500Principal(), e.getMessage(), e);
            return ValidationResult.failed(cert, e);
        }
    }

    /**
     * Determines whether the chain is anchored in the CA folder or the TSL store.
     */
    private TrustSource determineTrustSource(PKIXCertPathBuilderResult pkixResult) {
        if (pkixResult.getTrustAnchor() != null) {
            X509Certificate trustAnchor = pkixResult.getTrustAnchor().getTrustedCert();
            if (tslStore.isFromCaFolder(trustAnchor)) {
                return TrustSource.CA_FOLDER;
            }
        }
        for (java.security.cert.Certificate c : pkixResult.getCertPath().getCertificates()) {
            if (c instanceof X509Certificate xc && tslStore.isFromCaFolder(xc)) {
                return TrustSource.CA_FOLDER;
            }
        }
        return TrustSource.TSL;
    }

    /**
     * Checks whether the given certificate was loaded from the local CA folder
     * (as opposed to the remote TSL).
     *
     * @param cert certificate to check
     * @return {@code true} if the cert is in the CA folder set
     */
    public boolean isFromCaFolder(X509Certificate cert) {
        return tslStore.isFromCaFolder(cert);
    }

    /**
     * Builds a certificate chain for the given cert using the TSL keystore.
     *
     * @param localization application localization
     * @param cert         certificate whose chain to build
     * @return chain certificates (excluding the leaf), or empty set on failure
     */
    public Set<X509Certificate> buildChain(Localization localization, X509Certificate cert) {
        try {
            KeyStore keystore = tslStore.loadKeyStore(localization);
            return chainWalker.buildChain(keystore, cert);
        } catch (Exception e) {
            log.error("Failed to build chain for cert subject={}: {}",
                    cert.getSubjectX500Principal(), e.getMessage(), e);
            return new HashSet<>();
        }
    }

    /**
     * Downloads the TSL and returns all unexpired certificates from it.
     *
     * @param localization application localization (provides TSL URL)
     * @return set of TSL certificates, or empty set on failure
     */
    public Set<X509Certificate> downloadTsl(Localization localization) {
        try {
            return tslStore.downloadTsl(localization);
        } catch (Exception e) {
            log.error("Failed to download TSL: {}", e.getMessage(), e);
            return new HashSet<>();
        }
    }

    /** Trust source for a validated certificate. */
    public enum TrustSource {
        /** Certificate chain is anchored in the Trusted Service List. */
        TSL,
        /** Certificate chain is anchored in the local CA folder. */
        CA_FOLDER
    }

    /**
     * Result of certificate chain validation.
     *
     * @param pkixResult  PKIX path builder result (null if chain not found)
     * @param chain       the discovered certificate chain (may be empty)
     * @param trustSource where the chain was anchored (null if not validated)
     * @param error       exception that caused validation failure (null on success)
     */
    public record ValidationResult(
            PKIXCertPathBuilderResult pkixResult,
            Set<X509Certificate> chain,
            TrustSource trustSource,
            Exception error
    ) {
        /** Returns {@code true} if validation succeeded with no error. */
        public boolean isSuccess() {
            return error == null && pkixResult != null;
        }

        /** Creates an empty result for a certificate with no chain found. */
        public static ValidationResult empty(X509Certificate cert) {
            return new ValidationResult(null, new HashSet<>(), null, null);
        }

        /** Creates a failed result with the given error. */
        public static ValidationResult failed(X509Certificate cert, Exception error) {
            return new ValidationResult(null, new HashSet<>(), null, error);
        }
    }
}
