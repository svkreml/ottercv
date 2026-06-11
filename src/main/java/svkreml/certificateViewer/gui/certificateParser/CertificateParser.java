package svkreml.certificateViewer.gui.certificateParser;


import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.encoders.Hex;
import svkreml.certificateViewer.gui.api.model.CertificateModel;
import svkreml.certificateViewer.gui.api.model.DetailType;
import svkreml.certificateViewer.gui.localization.ru.Localization;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

@Slf4j
public class CertificateParser {

    private static final String SHA1 = "SHA-1";
    private static final String SHA256 = "SHA-256";
    private static final int HEX_RADIX = 16;
    private static final String VERSION_PREFIX = "V";

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
        addBasicDetails(localization, x509CertificateHolder, issuer, subject, certificateGeneralInfo, certificateDetails);
        addPublicKeyDetails(localization, x509CertificateHolder, certificateDetails);
        addExtensionDetails(localization, x509CertificateHolder, certificateDetails);
        addThumbprints(localization, x509CertificateHolder, certificateDetails);

        return new CertificateModel(certificateGeneralInfo, certificateDetails);
    }

    private static void addBasicDetails(Localization localization,
                                        X509CertificateHolder holder,
                                        Map<ASN1ObjectIdentifier, String> issuer,
                                        Map<ASN1ObjectIdentifier, String> subject,
                                        CertificateModel.CertificateGeneralInfo info,
                                        List<CertificateModel.CertificateDetail> details) {
        details.add(new CertificateModel.CertificateDetail(localization.TAB_DETAIL_TABLE_KEY_VERSION,
                VERSION_PREFIX + (holder.getVersionNumber()), null, DetailType.PROP));
        details.add(new CertificateModel.CertificateDetail(localization.TAB_DETAIL_TABLE_KEY_SERIAL_NUMBER,
                holder.getSerialNumber().toString(HEX_RADIX), null, DetailType.PROP));
        details.add(new CertificateModel.CertificateDetail(localization.TAB_DETAIL_TABLE_KEY_ALG,
                localization.convertOidToString(holder.getSignatureAlgorithm().getAlgorithm()),
                null, DetailType.PROP));
        details.add(new CertificateModel.CertificateDetail(localization.TAB_DETAIL_TABLE_KEY_ISSUER,
                parseX500ToTextArea(issuer), null, DetailType.PROP));
        details.add(new CertificateModel.CertificateDetail(localization.TAB_DETAIL_TABLE_KEY_VALID_FROM,
                localization.formatDate(info.getValidFrom()), null, DetailType.PROP));
        details.add(new CertificateModel.CertificateDetail(localization.TAB_DETAIL_TABLE_KEY_VALID_UNTIL,
                localization.formatDate(info.getValidTo()), null, DetailType.PROP));
        details.add(new CertificateModel.CertificateDetail(localization.TAB_DETAIL_TABLE_KEY_SUBJECT,
                parseX500ToTextArea(subject), null, DetailType.PROP));
    }

    private static void addPublicKeyDetails(Localization localization,
                                            X509CertificateHolder holder,
                                            List<CertificateModel.CertificateDetail> details) throws Exception {
        details.add(new CertificateModel.CertificateDetail(localization.TAB_DETAIL_TABLE_KEY_PUBLIC_KEY,
                localization.convertOidToString(holder.getSubjectPublicKeyInfo().getAlgorithm().getAlgorithm()),
                holder.getSubjectPublicKeyInfo().getPublicKeyData().getString().substring(1),
                DetailType.PROP));

        KeyInfo keyInfo = KeyParser.getKeyInfo(
                KeyParser.loadCertificate(holder.getEncoded()).getPublicKey());
        String exponentPart = (keyInfo.getExponent() != null)
                ? ("\n" + localization.TAB_DETAIL_TABLE_KEY_PUBLIC_KEY_RSA_EXP + " " + keyInfo.getExponent())
                : "";
        details.add(new CertificateModel.CertificateDetail(localization.TAB_DETAIL_TABLE_KEY_PUBLIC_KEY_DETAILS,
                localization.TAB_DETAIL_TABLE_KEY_PUBLIC_KEY_LENGTH + " " + keyInfo.getSize() +
                        "\n" + localization.TAB_DETAIL_TABLE_KEY_PUBLIC_KEY_ALG + " " + keyInfo.getAlgorithm() +
                        "\n" + localization.TAB_DETAIL_TABLE_KEY_PUBLIC_KEY_PARAMS + " " + keyInfo.getDetailedAlgorithm() +
                        exponentPart,
                null, DetailType.PROP));
    }

    private static void addExtensionDetails(Localization localization,
                                            X509CertificateHolder holder,
                                            List<CertificateModel.CertificateDetail> details) {
        for (Object extensionOID : holder.getExtensionOIDs()) {
            Extension extension = holder.getExtension((ASN1ObjectIdentifier) extensionOID);
            try {
                details.add(ExtensionParser.parseExtension(localization, extension));
            } catch (Exception e) {
                try {
                    details.add(new CertificateModel.CertificateDetail(
                            localization.convertOidToString(extension.getExtnId()) + ", " + extension.getExtnId().getId(),
                            e.getMessage(), extension.getParsedValue().toString(),
                            extension.isCritical() ? DetailType.CRIT_EXT : DetailType.NON_CRIT_EXT));
                    log.debug("Failed to parse extension", e);
                } catch (Exception ex) {
                    details.add(new CertificateModel.CertificateDetail(
                            localization.convertOidToString(extension.getExtnId()) + ", " + extension.getExtnId().getId(),
                            e.getMessage(), null,
                            extension.isCritical() ? DetailType.CRIT_EXT : DetailType.NON_CRIT_EXT));
                    log.debug("Failed to parse extension fallback", ex);
                }
            }
        }
    }

    private static void addThumbprints(Localization localization,
                                       X509CertificateHolder holder,
                                       List<CertificateModel.CertificateDetail> details)
            throws NoSuchAlgorithmException, java.io.IOException {
        details.add(new CertificateModel.CertificateDetail(localization.TAB_DETAIL_TABLE_KEY_THUMBPRINT_ALG,
                "SHA1", null, DetailType.THUMBPRINT));
        details.add(new CertificateModel.CertificateDetail(localization.TAB_DETAIL_TABLE_KEY_THUMBPRINT_VALUE,
                getThumbprint(holder.getEncoded(), SHA1), null, DetailType.THUMBPRINT));

        details.add(new CertificateModel.CertificateDetail(localization.TAB_DETAIL_TABLE_KEY_THUMBPRINT_ALG,
                "SHA256", null, DetailType.THUMBPRINT));
        details.add(new CertificateModel.CertificateDetail(localization.TAB_DETAIL_TABLE_KEY_THUMBPRINT_VALUE,
                getThumbprint(holder.getEncoded(), SHA256), null, DetailType.THUMBPRINT));
    }

    public static Map<ASN1ObjectIdentifier, String> x500NameToMap(X500Name x500Name) {
        Map<ASN1ObjectIdentifier, String> map = new LinkedHashMap<>();
        RDN[] rdNs = x500Name.getRDNs();
        for (int index = rdNs.length - 1; index >= 0; index--) {
            RDN rdn = rdNs[index];
            map.put(rdn.getFirst().getType(), rdn.getFirst().getValue().toString());
        }
        return map;
    }

    public static String getThumbprintSha1(byte[] cert) throws NoSuchAlgorithmException {
        return getThumbprint(cert, SHA1);
    }

    public static String getThumbprintSha256(byte[] cert) throws NoSuchAlgorithmException {
        return getThumbprint(cert, SHA256);
    }

    private static String getThumbprint(byte[] cert, String algorithm) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(algorithm);
        md.update(cert);
        return Hex.toHexString(md.digest()).toLowerCase();
    }

    public static String parseX500ToTextArea(Map<ASN1ObjectIdentifier, String> x500) {
        return x500.entrySet().stream()
                .map(e -> {
                    String[] name = X500Name.getDefaultStyle().oidToAttrNames(e.getKey());
                    return (name.length > 0 ? name[0].toUpperCase() : e.getKey().getId()) + " = " + e.getValue();
                })
                .collect(java.util.stream.Collectors.joining("\n"));
    }

}
