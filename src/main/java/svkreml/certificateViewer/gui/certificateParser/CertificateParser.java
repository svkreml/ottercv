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
        return x500.entrySet().stream()
                .map(e -> {
                    String[] name = X500Name.getDefaultStyle().oidToAttrNames(e.getKey());
                    return (name.length > 0 ? name[0].toUpperCase() : e.getKey().getId()) + " = " + e.getValue();
                })
                .collect(java.util.stream.Collectors.joining("\n"));
    }

}
