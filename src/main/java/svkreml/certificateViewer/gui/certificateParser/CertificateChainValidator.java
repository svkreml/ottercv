package svkreml.certificateViewer.gui.certificateParser;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import svkreml.certificateViewer.gui.localization.ru.Localization;

import java.security.KeyStore;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

@Slf4j
public class CertificateChainValidator {

    private final TslStore tslStore = new TslStore();
    private final ChainWalker chainWalker = new ChainWalker();

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

    private TrustSource determineTrustSource(PKIXCertPathBuilderResult pkixResult) {
        if (pkixResult.getTrustAnchor() != null) {
            X509Certificate trustAnchor = pkixResult.getTrustAnchor().getTrustedCert();
            if (tslStore.isFromCaFolder(trustAnchor)) {
                return TrustSource.CA_FOLDER;
            }
        }
        for (java.security.cert.Certificate c : pkixResult.getCertPath().getCertificates()) {
            if (tslStore.isFromCaFolder((X509Certificate) c)) {
                return TrustSource.CA_FOLDER;
            }
        }
        return TrustSource.TSL;
    }

    public boolean isFromCaFolder(X509Certificate cert) {
        return tslStore.isFromCaFolder(cert);
    }

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

    public Set<X509Certificate> downloadTsl(Localization localization) {
        try {
            return tslStore.downloadTsl(localization);
        } catch (Exception e) {
            log.error("Failed to download TSL: {}", e.getMessage(), e);
            return new HashSet<>();
        }
    }

    public enum TrustSource {
        TSL, CA_FOLDER
    }

    public record ValidationResult(
            PKIXCertPathBuilderResult pkixResult,
            Set<X509Certificate> chain,
            TrustSource trustSource,
            Exception error
    ) {
        public boolean isSuccess() {
            return error == null && pkixResult != null;
        }

        public static ValidationResult empty(X509Certificate cert) {
            return new ValidationResult(null, new HashSet(), null, null);
        }

        public static ValidationResult failed(X509Certificate cert, Exception error) {
            return new ValidationResult(null, new HashSet(), null, error);
        }
    }
}
