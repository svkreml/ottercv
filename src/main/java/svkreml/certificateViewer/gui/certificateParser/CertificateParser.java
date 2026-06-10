package svkreml.certificateViewer.gui.certificateParser;


import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.Streams;
import svkreml.certificateViewer.gui.api.model.CertificateModel;
import svkreml.certificateViewer.gui.api.model.CertificateStatus;
import svkreml.certificateViewer.gui.api.model.DetailType;
import svkreml.certificateViewer.gui.certificateParser.chainBuilder.CertificateVerifier;
import svkreml.certificateViewer.gui.localization.ru.Localization;
import svkreml.certificateViewer.gui.view.utils.Utils;
import svkreml.certificateViewer.gui.view.utils.WebUtils;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.X509Certificate;
import java.util.*;

@Slf4j
public class CertificateParser {
    static {
        if (!(X500Name.getDefaultStyle() instanceof CustomBCStyle)) {
            X500Name.setDefaultStyle(new CustomBCStyle());
        }
    }

    public static CertificateModel getCertificateModel(Localization localization,
                                                       X509CertificateHolder x509CertificateHolder) throws Exception {

        Map<ASN1ObjectIdentifier, String> issuer = x500NameToMap(x509CertificateHolder.getIssuer());
        Map<ASN1ObjectIdentifier, String> subject = x500NameToMap(x509CertificateHolder.getSubject());


        CertificateModel.CertificateGeneralInfo certificateGeneralInfo = new CertificateModel.CertificateGeneralInfo(
                issuer.get(X500Name.getDefaultStyle().attrNameToOID("CN")),
                subject.get(X500Name.getDefaultStyle().attrNameToOID("CN")),
                x509CertificateHolder.getNotBefore(),
                x509CertificateHolder.getNotAfter()
        );

        List<CertificateModel.CertificateDetail> certificateDetails = new ArrayList<>();
        certificateDetails.add(new CertificateModel.CertificateDetail(localization.TAB_DETAIL_TABLE_KEY_VERSION,
                "V" + (x509CertificateHolder.getVersionNumber()),
                null,
                DetailType.PROP));
        certificateDetails.add(new CertificateModel.CertificateDetail(localization.TAB_DETAIL_TABLE_KEY_SERIAL_NUMBER,
                x509CertificateHolder.getSerialNumber().toString(16),
                null,
                DetailType.PROP));
        certificateDetails.add(new CertificateModel.CertificateDetail(localization.TAB_DETAIL_TABLE_KEY_ALG,
                localization.convertOidToString(x509CertificateHolder.getSignatureAlgorithm().getAlgorithm()),
                null,
                DetailType.PROP));
        certificateDetails.add(new CertificateModel.CertificateDetail(localization.TAB_DETAIL_TABLE_KEY_ISSUER,
                parseX500ToTextArea(issuer),
                null,
                DetailType.PROP));
        certificateDetails.add(new CertificateModel.CertificateDetail(localization.TAB_DETAIL_TABLE_KEY_VALID_FROM,
                localization.formatDate(certificateGeneralInfo.getValidFrom()),
                null,
                DetailType.PROP));
        certificateDetails.add(new CertificateModel.CertificateDetail(localization.TAB_DETAIL_TABLE_KEY_VALID_UNTIL,
                localization.formatDate(certificateGeneralInfo.getValidTo()),
                null,
                DetailType.PROP));
        certificateDetails.add(new CertificateModel.CertificateDetail(localization.TAB_DETAIL_TABLE_KEY_SUBJECT,
                parseX500ToTextArea(subject),
                null,
                DetailType.PROP));

        certificateDetails.add(new CertificateModel.CertificateDetail(localization.TAB_DETAIL_TABLE_KEY_PUBLIC_KEY,
                localization.convertOidToString(x509CertificateHolder.getSubjectPublicKeyInfo()
                        .getAlgorithm()
                        .getAlgorithm())
                , x509CertificateHolder.getSubjectPublicKeyInfo().getPublicKeyData().getString().substring(1)
                , DetailType.PROP));

        KeyInfo
                keyInfo =
                KeyParser.getKeyInfo(KeyParser.loadCertificate(x509CertificateHolder.getEncoded()).getPublicKey());
        certificateDetails.add(new CertificateModel.CertificateDetail(localization.TAB_DETAIL_TABLE_KEY_PUBLIC_KEY_DETAILS,
                localization.TAB_DETAIL_TABLE_KEY_PUBLIC_KEY_LENGTH +
                        " " +
                        keyInfo.getSize()
                        +
                        "\n" +
                        localization.TAB_DETAIL_TABLE_KEY_PUBLIC_KEY_ALG +
                        " " +
                        keyInfo.getAlgorithm() +
                        "\n" +
                        localization.TAB_DETAIL_TABLE_KEY_PUBLIC_KEY_PARAMS +
                        " " +
                        keyInfo.getDetailedAlgorithm() +
                        ((keyInfo.getExponent() != null) ?
                                ("\n" +
                                        localization.TAB_DETAIL_TABLE_KEY_PUBLIC_KEY_RSA_EXP +
                                        " " +
                                        keyInfo.getExponent()) :
                                "")
                , null
                , DetailType.PROP));

        for (Object extensionOID : x509CertificateHolder.getExtensionOIDs()) {
            Extension extension = x509CertificateHolder.getExtension((ASN1ObjectIdentifier) extensionOID);
            try {
                certificateDetails.add(ExtensionParser.parseExtension(localization, extension));
            } catch (Exception e) {
                try {
                    certificateDetails.add(new CertificateModel.CertificateDetail(
                            localization.convertOidToString(extension.getExtnId()) +
                                    ", " +
                                    extension.getExtnId().getId(),
                            e.getMessage(),
                            extension.getParsedValue().toString(),
                            extension.isCritical() ? DetailType.CRIT_EXT : DetailType.NON_CRIT_EXT)
                    );
                    log.debug("Failed to parse extension", e);
                } catch (Exception ex) {
                    certificateDetails.add(new CertificateModel.CertificateDetail(
                            localization.convertOidToString(extension.getExtnId()) +
                                    ", " +
                                    extension.getExtnId().getId(),
                            e.getMessage(),
                            null,
                            extension.isCritical() ? DetailType.CRIT_EXT : DetailType.NON_CRIT_EXT)
                    );
                    log.debug("Failed to parse extension fallback", ex);
                }
            }
        }

        certificateDetails.add(new CertificateModel.CertificateDetail(localization.TAB_DETAIL_TABLE_KEY_THUMBPRINT_ALG,
                "SHA1",
                null,
                DetailType.THUMBPRINT));
        certificateDetails.add(new CertificateModel.CertificateDetail(localization.TAB_DETAIL_TABLE_KEY_THUMBPRINT_VALUE,
                getThumbprintSha1(x509CertificateHolder.getEncoded()),
                null,
                DetailType.THUMBPRINT));

        certificateDetails.add(new CertificateModel.CertificateDetail(localization.TAB_DETAIL_TABLE_KEY_THUMBPRINT_ALG,
                "SHA256",
                null,
                DetailType.THUMBPRINT));
        certificateDetails.add(new CertificateModel.CertificateDetail(localization.TAB_DETAIL_TABLE_KEY_THUMBPRINT_VALUE,
                getThumbprintSha256(x509CertificateHolder.getEncoded()),
                null,
                DetailType.THUMBPRINT));

        return new CertificateModel(certificateGeneralInfo, certificateDetails);
    }

    public static Map<ASN1ObjectIdentifier, String> x500NameToMap(X500Name x500Name) {
        Map<ASN1ObjectIdentifier, String> map = new LinkedHashMap<>();
        RDN[] rdNs = x500Name.getRDNs();
        for (int i = rdNs.length - 1; i >= 0; i--) {
            RDN rdn = rdNs[i];
            map.put(rdn.getFirst().getType(), rdn.getFirst().getValue().toString());
        }
        return map;
    }

    public static String getThumbprintSha1(byte[] cert) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        md.update(cert);
        byte[] digest = md.digest();
        String digestHex = Hex.toHexString(digest);
        return digestHex.toLowerCase();
    }

    public static String getThumbprintSha256(byte[] cert) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(cert);
        byte[] digest = md.digest();
        String digestHex = Hex.toHexString(digest);
        return digestHex.toLowerCase();
    }

    public static String parseX500ToTextArea(Map<ASN1ObjectIdentifier, String> x500) {
        StringBuilder stringBuilder = new StringBuilder();
        x500.forEach((k, v) -> {
            String[] name = X500Name.getDefaultStyle().oidToAttrNames(k);
            stringBuilder.append(
                    name.length > 0 ? name[0].toUpperCase() : k.getId()
            ).append(" = ").append(v).append("\n");
        });
        return stringBuilder.deleteCharAt(stringBuilder.length() - 1).toString();
    }

    @Getter
    @Setter
    public static class Validate {
        private Localization localization;
        private X509CertificateHolder x509CertificateHolder;
        private List<String> verificationDetails;
        private CertificateStatus certificateStatus;
        private ArrayList<CertificateModel.CertificateChain> certificateChains;

        public Validate(Localization localization, X509CertificateHolder x509CertificateHolder) {
            this.localization = localization;
            this.x509CertificateHolder = x509CertificateHolder;
        }

        private static CertificateStatus getCertificateStatus(X509CertificateHolder x509CertificateHolder,
                                                              List<String> verificationDetails,
                                                              CertificateVerifier certificateVerifier) {
            X509Certificate cert;
            try {
                cert = KeyParser.loadCertificate(x509CertificateHolder.getEncoded());
            } catch (Exception e) {
                log.error("Failed to parse certificate for status check", e);
                if (verificationDetails != null) verificationDetails.add("Failed to parse certificate: " + e.getMessage());
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
                    X509Certificate xc = (X509Certificate) c;
                    log.debug("Checking chain cert subject={}, isFromCaFolder={}",
                            xc.getSubjectX500Principal(), TrustChainBuilder.isFromCaFolder(xc));
                    if (TrustChainBuilder.isFromCaFolder(xc)) {
                        trustedViaCaFolder = true;
                        break;
                    }
                }
                if (!trustedViaCaFolder && verifiedCertChain.getTrustAnchor() != null) {
                    X509Certificate ta = verifiedCertChain.getTrustAnchor().getTrustedCert();
                    log.debug("Checking trust anchor subject={}, isFromCaFolder={}",
                            ta.getSubjectX500Principal(), TrustChainBuilder.isFromCaFolder(ta));
                    trustedViaCaFolder = TrustChainBuilder.isFromCaFolder(ta);
                }

                String statusMsg = trustedViaCaFolder ? Messages.CERTIFICATE_TRUSTED_VIA_CA_FOLDER : Messages.CERTIFICATE_IN_TSL;
                log.info("Trust source: {}", trustedViaCaFolder ? "CA_FOLDER" : "TSL");
                if (verificationDetails != null) {
                    verificationDetails.add(statusMsg);
                }
                certificateStatus = CertificateStatus.TRUSTED;
            } catch (Exception e) {
                log.error("Certificate verification failed for subject={}: {}",
                        cert.getSubjectX500Principal(), e.getMessage(), e);
                if (verificationDetails != null) verificationDetails.add(e.getMessage());
                Throwable cause = e.getCause();
                while (cause != null) {
                    if (verificationDetails != null) verificationDetails.add(cause.getMessage());
                    log.debug("Cause: {}", cause.getMessage());
                    cause = cause.getCause();
                }
                certificateStatus = CertificateStatus.BROKEN;
            }
            return certificateStatus;
        }

        public Validate invoke() throws
                CertificateException,
                NoSuchAlgorithmException,
                NoSuchProviderException,
                InvalidAlgorithmParameterException,
                IOException {
            verificationDetails = new ArrayList<>();
            Set<X509Certificate> gostTlsStore;
            try {
                log.debug("Building trust chain for cert subject={}", x509CertificateHolder.getSubject());
                gostTlsStore = TrustChainBuilder.smallInit(localization, x509CertificateHolder);
                log.info("Trust chain built, size={}", gostTlsStore.size());
            } catch (Exception e) {
                log.error("Failed to initialize trust chain builder", e);
                verificationDetails.add(e.getMessage());
                gostTlsStore = new HashSet<>();
            }
            certificateChains = new ArrayList<>();
            Map<ASN1ObjectIdentifier, String> subject = x500NameToMap(x509CertificateHolder.getSubject());


            if (!gostTlsStore.isEmpty()) {
                log.info("TSL store has {} certificates, building chain via TSL", gostTlsStore.size());
                CertificateVerifier certificateVerifier = new CertificateVerifier(gostTlsStore);
                certificateStatus =
                        getCertificateStatus(x509CertificateHolder, verificationDetails, certificateVerifier);
                log.debug("Main cert status: {}", certificateStatus);

                certificateChains.add(new CertificateModel.CertificateChain(
                        subject.get(X500Name.getDefaultStyle().attrNameToOID("CN")),
                        certificateStatus, x509CertificateHolder, verificationDetails));
                for (X509Certificate x509Certificate : gostTlsStore) {
                    X509CertificateHolder
                            x509CertificateHolder1 =
                            new X509CertificateHolder(x509Certificate.getEncoded());
                    List<String> verificationDetails1 = new ArrayList<>();
                    certificateChains.add(new CertificateModel.CertificateChain(
                            x500NameToMap(x509CertificateHolder1.getSubject()).get(X500Name.getDefaultStyle()
                                    .attrNameToOID("CN")),
                            getCertificateStatus(x509CertificateHolder1, verificationDetails1, certificateVerifier),
                            x509CertificateHolder1, verificationDetails1));
                }
            } else {
                log.warn("TSL store is empty, marking as UNTRUSTED_ROOT");
                certificateStatus = CertificateStatus.UNTRUSTED_ROOT;
                certificateChains.add(
                        new CertificateModel.CertificateChain(
                                subject.get(X500Name.getDefaultStyle().attrNameToOID("CN")),
                                certificateStatus, x509CertificateHolder, verificationDetails));
                X509CertificateHolder x509CertificateHolder = this.x509CertificateHolder;
                while (true) {
                    X509CertificateHolder x509CertificateHolder1 = getCa(x509CertificateHolder);
                    if (x509CertificateHolder1 == null) break;
                    List<String> verificationDetails1 = new ArrayList<>();
                    certificateChains.add(new CertificateModel.CertificateChain(
                            x500NameToMap(x509CertificateHolder1.getSubject()).get(X500Name.getDefaultStyle()
                                    .attrNameToOID("CN")),
                            CertificateStatus.UNTRUSTED_ROOT,
                            x509CertificateHolder1, verificationDetails1));
                    x509CertificateHolder = x509CertificateHolder1;
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
                    if (accessDescription.getAccessMethod().getId().equals("1.3.6.1.5.5.7.48.2")) {
                        byte[]
                                bytes =
                                Streams.readAllLimited(WebUtils.download(accessDescription.getAccessLocation()
                                        .toASN1Primitive()
                                        .toString()
                                        .split("]", 2)[1]), 20000);
                        return new X509CertificateHolder(Utils.clearCertBytes(bytes));
                    }
                }
            } catch (Exception e) {
                log.debug("Failed to get CA certificate", e);
            }
            return null;
        }
    }

}
