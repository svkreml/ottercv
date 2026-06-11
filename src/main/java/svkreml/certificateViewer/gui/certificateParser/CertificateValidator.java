package svkreml.certificateViewer.gui.certificateParser;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.experimental.Accessors;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.io.Streams;
import svkreml.certificateViewer.gui.api.model.CertificateModel;
import svkreml.certificateViewer.gui.api.model.CertificateStatus;
import svkreml.certificateViewer.gui.localization.ru.Localization;
import svkreml.certificateViewer.gui.view.utils.Utils;
import svkreml.certificateViewer.gui.view.utils.WebUtils;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * Validates an X.509 certificate by building its trust chain and verifying PKIX constraints.
 * <p>
 * This class orchestrates:
 * <ol>
 *   <li>Chain building via {@link CertificateChainValidator}</li>
 *   <li>PKIX path verification via {@link CertificateVerifier}</li>
 *   <li>Trust source determination (TSL vs CA folder)</li>
 *   <li>Building a list of {@link CertificateModel.CertificateChain} for GUI display</li>
 * </ol>
 *
 * <h3>Usage</h3>
 * <pre>{@code
 * var validator = new CertificateValidator(localization, holder);
 * validator.invoke();
 * CertificateStatus status = validator.getCertificateStatus();
 * List<CertificateChain> chains = validator.getCertificateChains();
 * }</pre>
 */
@Slf4j
@Getter
@Setter
@Accessors(chain = true)
@FieldDefaults(level = AccessLevel.PRIVATE)
@RequiredArgsConstructor
public class CertificateValidator {

    private static final String CA_ISSUERS_OID = "1.3.6.1.5.5.7.48.2";
    private static final int MAX_CERT_BYTES = 20000;
    private static final CertificateChainValidator chainValidator = new CertificateChainValidator();

    final Localization localization;
    final X509CertificateHolder x509CertificateHolder;
    List<String> verificationDetails;
    CertificateStatus certificateStatus;
    ArrayList<CertificateModel.CertificateChain> certificateChains;

    private static void addDetail(List<String> details, String message) {
        if (details != null) {
            details.add(message);
        }
    }

    private static CertificateStatus getCertificateStatus(X509CertificateHolder x509CertificateHolder,
                                                           List<String> verificationDetails,
                                                           CertificateVerifier certificateVerifier) {
        X509Certificate cert;
        try {
            cert = KeyParser.loadCertificate(x509CertificateHolder.getEncoded());
        } catch (Exception e) {
            log.error("Failed to parse certificate for status check", e);
            addDetail(verificationDetails, "Failed to parse certificate: " + e.getMessage());
            return CertificateStatus.BROKEN;
        }
        CertificateStatus certificateStatus;
        try {
            log.debug("Verifying cert subject={}", cert.getSubjectX500Principal());
            PKIXCertPathBuilderResult verifiedCertChain = certificateVerifier.verifyCertificate(cert);
            log.debug("Verification succeeded, chain length={}, trustAnchor={}",
                    verifiedCertChain.getCertPath().getCertificates().size(),
                    verifiedCertChain.getTrustAnchor() != null ?
                            verifiedCertChain.getTrustAnchor().getTrustedCert().getSubjectX500Principal() : "null");

            boolean trustedViaCaFolder = false;
            for (java.security.cert.Certificate c : verifiedCertChain.getCertPath().getCertificates()) {
                if (c instanceof X509Certificate xc) {
                    log.debug("Checking chain cert subject={}, isFromCaFolder={}",
                            xc.getSubjectX500Principal(), chainValidator.isFromCaFolder(xc));
                    if (chainValidator.isFromCaFolder(xc)) {
                        trustedViaCaFolder = true;
                        break;
                    }
                }
            }
            if (!trustedViaCaFolder && verifiedCertChain.getTrustAnchor() != null) {
                X509Certificate ta = verifiedCertChain.getTrustAnchor().getTrustedCert();
                log.debug("Checking trust anchor subject={}, isFromCaFolder={}",
                        ta.getSubjectX500Principal(), chainValidator.isFromCaFolder(ta));
                trustedViaCaFolder = chainValidator.isFromCaFolder(ta);
            }

            String statusMsg = trustedViaCaFolder ? Messages.CERTIFICATE_TRUSTED_VIA_CA_FOLDER : Messages.CERTIFICATE_IN_TSL;
            log.info("Trust source: {}", trustedViaCaFolder ? "CA_FOLDER" : "TSL");
            addDetail(verificationDetails, statusMsg);
            certificateStatus = CertificateStatus.TRUSTED;
        } catch (Exception e) {
            log.error("Certificate verification failed for subject={}: {}",
                    cert.getSubjectX500Principal(), e.getMessage(), e);
            addDetail(verificationDetails, e.getMessage());
            Throwable cause = e.getCause();
            while (cause != null) {
                addDetail(verificationDetails, cause.getMessage());
                log.debug("Cause: {}", cause.getMessage());
                cause = cause.getCause();
            }
            certificateStatus = CertificateStatus.BROKEN;
        }
        return certificateStatus;
    }

    /**
     * Runs the full validation: builds chain, verifies PKIX, determines trust source,
     * and populates {@link #getCertificateChains()} for GUI display.
     *
     * @return this instance for chaining
     * @throws CertificateException on certificate errors
     * @throws NoSuchAlgorithmException on algorithm errors
     * @throws NoSuchProviderException on provider errors
     * @throws InvalidAlgorithmParameterException on parameter errors
     * @throws IOException on I/O errors
     */
    public CertificateValidator invoke() throws
            CertificateException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            InvalidAlgorithmParameterException,
            IOException {
        verificationDetails = new ArrayList<>();
        Set<X509Certificate> chainCerts;
        try {
            log.debug("Building trust chain for cert subject={}", x509CertificateHolder.getSubject());
            chainCerts = chainValidator.buildChain(localization,
                    KeyParser.loadCertificate(x509CertificateHolder.getEncoded()));
            log.info("Trust chain built, size={}", chainCerts.size());
        } catch (Exception e) {
            log.error("Failed to initialize trust chain builder", e);
            verificationDetails.add(e.getMessage());
            chainCerts = new HashSet<>();
        }
        certificateChains = new ArrayList<>();
        Map<ASN1ObjectIdentifier, String> subject = CertificateParser.x500NameToMap(x509CertificateHolder.getSubject());

        if (!chainCerts.isEmpty()) {
            log.info("TSL store has {} certificates, building chain via TSL", chainCerts.size());
            CertificateVerifier certificateVerifier = new CertificateVerifier(chainCerts);
            certificateStatus =
                    getCertificateStatus(x509CertificateHolder, verificationDetails, certificateVerifier);
            log.debug("Main cert status: {}", certificateStatus);

            certificateChains.add(new CertificateModel.CertificateChain(
                    subject.get(X500Name.getDefaultStyle().attrNameToOID("CN")),
                    certificateStatus, x509CertificateHolder, verificationDetails));
            for (X509Certificate x509Certificate : chainCerts) {
                X509CertificateHolder chainHolder =
                        new X509CertificateHolder(x509Certificate.getEncoded());
                List<String> chainDetails = new ArrayList<>();
                certificateChains.add(new CertificateModel.CertificateChain(
                        CertificateParser.x500NameToMap(chainHolder.getSubject()).get(X500Name.getDefaultStyle()
                                .attrNameToOID("CN")),
                        getCertificateStatus(chainHolder, chainDetails, certificateVerifier),
                        chainHolder, chainDetails));
            }
        } else {
            log.warn("TSL store is empty, marking as UNTRUSTED_ROOT");
            certificateStatus = CertificateStatus.UNTRUSTED_ROOT;
            certificateChains.add(
                    new CertificateModel.CertificateChain(
                            subject.get(X500Name.getDefaultStyle().attrNameToOID("CN")),
                            certificateStatus, x509CertificateHolder, verificationDetails));
            X509CertificateHolder currentHolder = this.x509CertificateHolder;
            while (true) {
                X509CertificateHolder caHolder = getCa(currentHolder);
                if (caHolder == null) break;
                List<String> caDetails = new ArrayList<>();
                certificateChains.add(new CertificateModel.CertificateChain(
                        CertificateParser.x500NameToMap(caHolder.getSubject()).get(X500Name.getDefaultStyle()
                                .attrNameToOID("CN")),
                        CertificateStatus.UNTRUSTED_ROOT,
                        caHolder, caDetails));
                currentHolder = caHolder;
            }
        }

        return this;
    }

    private X509CertificateHolder getCa(X509CertificateHolder x509CertificateHolder) {
        try {
            AuthorityInformationAccess
                    instance =
                    AuthorityInformationAccess.fromExtensions(x509CertificateHolder.getExtensions());
            if (instance == null) return null;
            for (AccessDescription accessDescription : instance.getAccessDescriptions()) {
                if (accessDescription.getAccessMethod().getId().equals(CA_ISSUERS_OID)) {
                    byte[] bytes =
                            Streams.readAllLimited(WebUtils.download(accessDescription.getAccessLocation()
                                    .toASN1Primitive()
                                    .toString()
                                    .split("]", 2)[1]), MAX_CERT_BYTES);
                    return new X509CertificateHolder(Utils.clearCertBytes(bytes));
                }
            }
        } catch (Exception e) {
            log.debug("Failed to get CA certificate", e);
        }
        return null;
    }
}
