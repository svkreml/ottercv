package svkreml.certificateViewer.gui.certificateParser;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CRLEntryHolder;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.util.encoders.Hex;
import svkreml.certificateViewer.gui.api.model.CertificateModel;
import svkreml.certificateViewer.gui.api.model.CrlModel;
import svkreml.certificateViewer.gui.api.model.CrlStatus;
import svkreml.certificateViewer.gui.api.model.DetailType;
import svkreml.certificateViewer.gui.localization.ru.Localization;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * Parses an X.509 CRL into a display model.
 */
@Slf4j
public final class CrlParser {

    private static final String VERSION_PREFIX = "V";
    private static final int HEX_RADIX = 16;

    private CrlParser() {
    }

    public static CrlModel getCrlModel(Localization localization, X509CRLHolder holder) throws Exception {
        X500Name issuerName = holder.getIssuer();
        Map<ASN1ObjectIdentifier, String> issuer = CertificateParser.x500NameToMap(issuerName);
        String issuerCn = issuer.getOrDefault(
                X500Name.getDefaultStyle().attrNameToOID("CN"),
                issuerName.toString());

        int version = holder.toASN1Structure().getVersionNumber();
        String signatureAlgorithm = localization.convertOidToString(
                holder.toASN1Structure().getSignatureAlgorithm().getAlgorithm());
        String crlNumber = getCrlNumber(holder);
        int revokedCount = getRevokedCount(holder);

        CrlModel.CrlGeneralInfo generalInfo = new CrlModel.CrlGeneralInfo(
                issuerCn,
                CertificateParser.parseX500ToTextArea(issuer),
                holder.getThisUpdate(),
                holder.getNextUpdate(),
                VERSION_PREFIX + version,
                signatureAlgorithm,
                crlNumber,
                revokedCount);
        generalInfo.getStatus().setValue(CrlStatus.UNKNOWN);
        generalInfo.getStatusDetails().setValue(List.of(localization.CRL_CHECKING_SIGNATURE));

        List<CertificateModel.CertificateDetail> details = new ArrayList<>();
        addBasicDetails(localization, holder, issuer, generalInfo, details);
        addExtensionDetails(localization, holder.getExtensionOIDs(), holder::getExtension, details);
        addSignatureDetails(localization, holder, details);
        addThumbprints(localization, holder, details);

        List<CrlModel.RevokedCertificate> revokedCertificates =
                parseRevokedCertificates(localization, holder);

        return new CrlModel(generalInfo, details, revokedCertificates, holder);
    }

    private static void addBasicDetails(Localization localization,
                                        X509CRLHolder holder,
                                        Map<ASN1ObjectIdentifier, String> issuer,
                                        CrlModel.CrlGeneralInfo generalInfo,
                                        List<CertificateModel.CertificateDetail> details) {
        details.add(new CertificateModel.CertificateDetail(
                localization.TAB_DETAIL_TABLE_KEY_VERSION,
                generalInfo.getVersion(), null, DetailType.PROP));
        details.add(new CertificateModel.CertificateDetail(
                localization.TAB_DETAIL_TABLE_KEY_ALG,
                generalInfo.getSignatureAlgorithm(), null, DetailType.PROP));
        details.add(new CertificateModel.CertificateDetail(
                localization.TAB_DETAIL_TABLE_KEY_CRL_ISSUER,
                CertificateParser.parseX500ToTextArea(issuer), null, DetailType.PROP));
        details.add(new CertificateModel.CertificateDetail(
                localization.TAB_DETAIL_TABLE_KEY_CRL_THIS_UPDATE,
                localization.formatDate(holder.getThisUpdate()), null, DetailType.PROP));
        details.add(new CertificateModel.CertificateDetail(
                localization.TAB_DETAIL_TABLE_KEY_CRL_NEXT_UPDATE,
                holder.getNextUpdate() != null
                        ? localization.formatDate(holder.getNextUpdate())
                        : localization.NOT_AVAILABLE,
                null, DetailType.PROP));
        details.add(new CertificateModel.CertificateDetail(
                localization.TAB_DETAIL_TABLE_KEY_CRL_NUMBER,
                generalInfo.getCrlNumber() != null ? generalInfo.getCrlNumber() : localization.NOT_AVAILABLE,
                null, DetailType.PROP));
        details.add(new CertificateModel.CertificateDetail(
                localization.TAB_DETAIL_TABLE_KEY_CRL_REVOKED_COUNT,
                String.valueOf(generalInfo.getRevokedCount()), null, DetailType.PROP));
    }

    private static void addExtensionDetails(Localization localization,
                                            List<?> extensionOIDs,
                                            java.util.function.Function<ASN1ObjectIdentifier, Extension> extensionGetter,
                                            List<CertificateModel.CertificateDetail> details) {
        if (extensionOIDs == null) {
            return;
        }
        for (Object extensionOID : extensionOIDs) {
            if (!(extensionOID instanceof ASN1ObjectIdentifier oid)) {
                continue;
            }
            Extension extension = extensionGetter.apply(oid);
            if (extension == null) {
                continue;
            }
            details.add(parseExtension(localization, extension));
        }
    }

    private static CertificateModel.CertificateDetail parseExtension(Localization localization,
                                                                     Extension extension) {
        try {
            return ExtensionParser.parseExtension(localization, extension);
        } catch (Exception e) {
            String field = localization.convertOidToString(extension.getExtnId()) +
                    ", " + extension.getExtnId().getId();
            String detail;
            try {
                detail = extension.getParsedValue().toString();
            } catch (Exception ex) {
                detail = null;
            }
            log.debug("Failed to parse CRL extension {}", extension.getExtnId(), e);
            return new CertificateModel.CertificateDetail(
                    field,
                    e.getMessage(),
                    detail,
                    extension.isCritical() ? DetailType.CRIT_EXT : DetailType.NON_CRIT_EXT);
        }
    }

    private static void addSignatureDetails(Localization localization,
                                            X509CRLHolder holder,
                                            List<CertificateModel.CertificateDetail> details) {
        details.add(new CertificateModel.CertificateDetail(
                localization.TAB_DETAIL_TABLE_KEY_SIGNATURE_VALUE,
                Hex.toHexString(holder.toASN1Structure().getSignature().getBytes()),
                null, DetailType.PROP));
    }

    private static void addThumbprints(Localization localization,
                                       X509CRLHolder holder,
                                       List<CertificateModel.CertificateDetail> details) {
        try {
            details.add(new CertificateModel.CertificateDetail(
                    localization.TAB_DETAIL_TABLE_KEY_THUMBPRINT_ALG,
                    "SHA1", null, DetailType.THUMBPRINT));
            details.add(new CertificateModel.CertificateDetail(
                    localization.TAB_DETAIL_TABLE_KEY_THUMBPRINT_VALUE,
                    CertificateParser.getThumbprintSha1(holder.getEncoded()), null, DetailType.THUMBPRINT));
            details.add(new CertificateModel.CertificateDetail(
                    localization.TAB_DETAIL_TABLE_KEY_THUMBPRINT_ALG,
                    "SHA256", null, DetailType.THUMBPRINT));
            details.add(new CertificateModel.CertificateDetail(
                    localization.TAB_DETAIL_TABLE_KEY_THUMBPRINT_VALUE,
                    CertificateParser.getThumbprintSha256(holder.getEncoded()), null, DetailType.THUMBPRINT));
        } catch (Exception e) {
            log.warn("Failed to calculate CRL thumbprint", e);
        }
    }

    private static List<CrlModel.RevokedCertificate> parseRevokedCertificates(Localization localization,
                                                                              X509CRLHolder holder) {
        List<CrlModel.RevokedCertificate> result = new ArrayList<>();
        Collection<?> entries = holder.getRevokedCertificates();
        if (entries == null) {
            return result;
        }
        for (Object entryObject : entries) {
            if (!(entryObject instanceof X509CRLEntryHolder entry)) {
                continue;
            }
            String serialNumber = entry.getSerialNumber().toString(HEX_RADIX).toUpperCase();
            String reason = getRevocationReason(localization, entry);
            String certificateIssuer = entry.getCertificateIssuer() != null
                    ? entry.getCertificateIssuer().toString()
                    : null;

            List<CertificateModel.CertificateDetail> entryDetails = new ArrayList<>();
            entryDetails.add(new CertificateModel.CertificateDetail(
                    localization.TAB_DETAIL_TABLE_KEY_SERIAL_NUMBER,
                    serialNumber, null, DetailType.PROP));
            entryDetails.add(new CertificateModel.CertificateDetail(
                    localization.TAB_DETAIL_TABLE_KEY_REVOCATION_DATE,
                    localization.formatDate(entry.getRevocationDate()), null, DetailType.PROP));
            entryDetails.add(new CertificateModel.CertificateDetail(
                    localization.TAB_DETAIL_TABLE_KEY_REVOCATION_REASON,
                    reason != null ? reason : localization.NOT_AVAILABLE, null, DetailType.PROP));
            if (certificateIssuer != null) {
                entryDetails.add(new CertificateModel.CertificateDetail(
                        localization.TAB_DETAIL_TABLE_KEY_CERTIFICATE_ISSUER,
                        certificateIssuer, null, DetailType.PROP));
            }
            addExtensionDetails(localization, entry.getExtensionOIDs(), entry::getExtension, entryDetails);

            result.add(new CrlModel.RevokedCertificate(
                    serialNumber,
                    entry.getRevocationDate(),
                    reason,
                    certificateIssuer,
                    entryDetails));
        }
        return result;
    }

    private static String getRevocationReason(Localization localization, X509CRLEntryHolder entry) {
        Extension reasonExtension = entry.getExtension(Extension.reasonCode);
        if (reasonExtension == null) {
            return null;
        }
        try {
            CRLReason reason = CRLReason.getInstance(reasonExtension.getParsedValue());
            return localization.nameCrlReason(reason.getValue().intValue());
        } catch (Exception e) {
            log.debug("Failed to parse CRL entry reason", e);
            return null;
        }
    }

    private static String getCrlNumber(X509CRLHolder holder) {
        Extension extension = holder.getExtension(Extension.cRLNumber);
        if (extension == null) {
            return null;
        }
        try {
            return CRLNumber.getInstance(extension.getParsedValue()).getCRLNumber().toString();
        } catch (Exception e) {
            log.debug("Failed to parse CRL number", e);
            return null;
        }
    }

    private static int getRevokedCount(X509CRLHolder holder) {
        Collection<?> entries = holder.getRevokedCertificates();
        return entries == null ? 0 : entries.size();
    }
}
