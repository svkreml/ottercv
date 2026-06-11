package svkreml.certificateViewer.gui.certificateParser;

import lombok.experimental.UtilityClass;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.util.encoders.Hex;
import svkreml.certificateViewer.gui.api.model.CertificateModel;
import svkreml.certificateViewer.gui.api.model.DetailType;
import svkreml.certificateViewer.gui.localization.ru.Localization;

import java.text.ParseException;
import java.util.LinkedHashMap;
import java.util.Map;

@UtilityClass
public class ExtensionParser {

    private static final String OID_SUBJECT_SIGNATURE_TOOL = "1.2.643.100.111";
    private static final String ENTRY_SEPARATOR = "; ";
    private static final int ISSUER_SIGNATURE_TOOL_PARTS = 4;
    private static final String OID_ISSUER_SIGNATURE_TOOL = "1.2.643.100.112";
    private static final String OID_SUBJECT_KEY_IDENTIFIER = "2.5.29.14";
    private static final String OID_KEY_USAGE = "2.5.29.15";
    private static final String OID_PRIVATE_KEY_USAGE_PERIOD = "2.5.29.16";
    private static final String OID_SUBJECT_ALTERNATIVE_NAME = "2.5.29.17";
    private static final String OID_BASIC_CONSTRAINTS = "2.5.29.19";
    private static final String OID_CRL_DISTRIBUTION_POINTS = "2.5.29.31";
    private static final String OID_CERTIFICATE_POLICIES = "2.5.29.32";
    private static final String OID_AUTHORITY_KEY_IDENTIFIER = "2.5.29.35";
    private static final String OID_EXTENDED_KEY_USAGE = "2.5.29.37";
    private static final String OID_ENHANCED_KEY_USAGE = "1.3.6.1.4.1.311.21.10";
    private static final String OID_AUTHORITY_INFORMATION_ACCESS = "1.3.6.1.5.5.7.1.1";

    public static CertificateModel.CertificateDetail parseExtension(Localization localization, Extension extension)
            throws ParseException {
        StringBuilder parsedAsn1Ext = new StringBuilder();

        switch (extension.getExtnId().getId()) {
            case OID_SUBJECT_SIGNATURE_TOOL -> parseSubjectSignatureTool(extension, parsedAsn1Ext);
            case OID_ISSUER_SIGNATURE_TOOL -> parseIssuerSignatureTool(localization, extension, parsedAsn1Ext);
            case OID_SUBJECT_KEY_IDENTIFIER -> parseSubjectKeyIdentifier(localization, extension, parsedAsn1Ext);
            case OID_KEY_USAGE -> parseKeyUsage(localization, extension, parsedAsn1Ext);
            case OID_PRIVATE_KEY_USAGE_PERIOD -> parsePrivateKeyUsagePeriod(localization, extension, parsedAsn1Ext);
            case OID_SUBJECT_ALTERNATIVE_NAME -> parseSubjectAlternativeName(localization, extension, parsedAsn1Ext);
            case OID_BASIC_CONSTRAINTS -> parseBasicConstraints(localization, extension, parsedAsn1Ext);
            case OID_CRL_DISTRIBUTION_POINTS -> parseCertificateRevocationList(localization, extension, parsedAsn1Ext);
            case OID_CERTIFICATE_POLICIES -> parseCertificatePolices(localization, extension, parsedAsn1Ext);
            case OID_AUTHORITY_KEY_IDENTIFIER -> parseAuthorityKeyIdentifier(localization, extension, parsedAsn1Ext);
            case OID_EXTENDED_KEY_USAGE -> parseExtendedKeyUsage(localization, extension, parsedAsn1Ext);
            case OID_ENHANCED_KEY_USAGE -> parseEnhancedKeyUsage(localization, extension, parsedAsn1Ext);
            case OID_AUTHORITY_INFORMATION_ACCESS -> parseAuthorityInformationAccess(localization, extension, parsedAsn1Ext);
            default -> parsedAsn1Ext = new StringBuilder(extension.getParsedValue().toString());
        }

        return new CertificateModel.CertificateDetail(
                localization.convertOidToString(extension.getExtnId()) + ", " + extension.getExtnId().getId(),
                parsedAsn1Ext.toString(),
                null,
                extension.isCritical() ? DetailType.CRIT_EXT : DetailType.NON_CRIT_EXT);
    }

    private static void parseEnhancedKeyUsage(Localization localization,
                                              Extension extension,
                                              StringBuilder parsedAsn1Ext) {
        for (ASN1Encodable asn1Encodable : ((ASN1Sequence) extension.getParsedValue()).toArray()) {
            for (ASN1Encodable encodable : ((ASN1Sequence) asn1Encodable).toArray()) {
                parsedAsn1Ext.append(localization.convertOidToString((ASN1ObjectIdentifier) encodable, ""))
                        .append("(").append(encodable).append(")").append(ENTRY_SEPARATOR);
            }
            parsedAsn1Ext.append('\n');
        }

    }

    private static void parseSubjectAlternativeName(Localization localization,
                                                    Extension extension,
                                                    StringBuilder parsedAsn1Ext) {
        GeneralNames instance = GeneralNames.getInstance(extension.getParsedValue());
        GeneralName[] names = instance.getNames();
        for (GeneralName name : names) {
            parsedAsn1Ext.append(convertGeneralNameTag(name.getTagNo()))
                    .append(": ")
                    .append(name.getName().toString())
                    .append('\n');
        }

    }

    private static String convertGeneralNameTag(int tagNo) {
        return switch (tagNo) {
            case GeneralName.otherName -> "otherName";
            case GeneralName.rfc822Name -> "rfc822Name";
            case GeneralName.dNSName -> "dNSName";
            case GeneralName.x400Address -> "x400Address";
            case GeneralName.directoryName -> "directoryName";
            case GeneralName.ediPartyName -> "ediPartyName";
            case GeneralName.uniformResourceIdentifier -> "uniformResourceIdentifier";
            case GeneralName.iPAddress -> "iPAddress";
            case GeneralName.registeredID -> "registeredID";
            default -> String.valueOf(tagNo);
        };
    }

    private static void parseAuthorityInformationAccess(Localization localization,
                                                        Extension extension,
                                                        StringBuilder parsedAsn1Ext) {
        AuthorityInformationAccess instance = AuthorityInformationAccess.getInstance(extension.getParsedValue());
        for (AccessDescription accessDescription : instance.getAccessDescriptions()) {
            parsedAsn1Ext.append(localization.convertOidToString(accessDescription.getAccessMethod(), "")).
                    append("(")
                    .append(accessDescription.getAccessMethod().getId())
                    .append(")")
                    .append(" : ").
                    append(DERIA5String.getInstance(accessDescription.getAccessLocation().getName()).getString())
                    .append('\n');
        }
    }

    private static void parseBasicConstraints(Localization localization,
                                              Extension extension,
                                              StringBuilder parsedAsn1Ext) {
        BasicConstraints instance = BasicConstraints.getInstance(extension.getParsedValue());
        parsedAsn1Ext.append(localization.EXTENSIONS_IS_CA).append(" ").append(instance.isCA()).append("\n");
        parsedAsn1Ext.append(localization.EXTENSIONS_PATH_LEN_CONSTRAINT)
                .append(" ")
                .append(instance.getPathLenConstraint())
                .append("\n");
    }

    private static void parseCertificatePolices(Localization localization,
                                                Extension extension,
                                                StringBuilder parsedAsn1Ext) {
        CertificatePolicies instance = CertificatePolicies.getInstance(extension.getParsedValue());
        for (PolicyInformation policyInformation : instance.getPolicyInformation()) {
            ASN1Sequence policyQualifiers = policyInformation.getPolicyQualifiers();
            parsedAsn1Ext.append(localization.convertOidToString(policyInformation.getPolicyIdentifier(), ""))
                    .append("(").append(policyInformation.getPolicyIdentifier()).append(")");
            if (policyQualifiers != null)
                parsedAsn1Ext.append(policyQualifiers);
            parsedAsn1Ext.append('\n');
        }
    }

    private static void parseCertificateRevocationList(Localization localization,
                                                       Extension extension,
                                                       StringBuilder parsedAsn1Ext) {
        CRLDistPoint crlDistPoint = CRLDistPoint.getInstance(extension.getParsedValue());
        parsedAsn1Ext.append(crlDistPoint.toString()
                .replaceAll("([\\n\\r\\]]){4,}", "\n]]\n"));
    }

    private static void parsePrivateKeyUsagePeriod(Localization localization,
                                                   Extension extension,
                                                   StringBuilder parsedAsn1Ext) throws ParseException {
        PrivateKeyUsagePeriod instance = PrivateKeyUsagePeriod.getInstance(extension.getParsedValue());
        parsedAsn1Ext.append(String.format("%-15s %s",
                localization.EXTENSIONS_PRIVATE_KEY_VALID_FROM,
                localization.formatDate(instance.getNotBefore().getDate()))).append("\n");
        parsedAsn1Ext.append(String.format("%-15s %s",
                localization.EXTENSIONS_PRIVATE_KEY_VALID_TO,
                localization.formatDate(instance.getNotAfter().getDate()))).append("\n");
    }

    private static void parseExtendedKeyUsage(Localization localization,
                                              Extension extension,
                                              StringBuilder parsedAsn1Ext) {
        ExtendedKeyUsage instance = ExtendedKeyUsage.getInstance(extension.getParsedValue());
        for (KeyPurposeId usage : instance.getUsages()) {
            parsedAsn1Ext.append(localization.convertOidToString(usage.toOID()))
                    .append("(")
                    .append(usage.toOID())
                    .append(")")
                    .append("\n");
        }
    }

    private static void parseSubjectSignatureTool(Extension extension, StringBuilder parsedAsn1Ext) {
        parsedAsn1Ext.append("Наименовании средства ЭП Субъекта: ")
                .append(DERUTF8String.getInstance(DEROctetString.getInstance(extension.getExtnValue()).getOctets())
                        .getString());
    }

    private static void parseIssuerSignatureTool(Localization localization,
                                                 Extension extension,
                                                 StringBuilder parsedAsn1Ext) {

        ASN1Encodable[] instance = BERSequence.getInstance(DEROctetString.
                getInstance(extension.getExtnValue()).getOctets()).toArray();
        if (instance.length == ISSUER_SIGNATURE_TOOL_PARTS) {
            parsedAsn1Ext.append(String.format("%15s %s", "signTool:", instance[0].toString())).append("\n");
            parsedAsn1Ext.append(String.format("%15s %s", "cATool:", instance[1].toString())).append("\n");
            parsedAsn1Ext.append(String.format("%15s %s", "signToolCert:", instance[2].toString())).append("\n");
            parsedAsn1Ext.append(String.format("%15s %s", "cAToolCert:", instance[3].toString())).append("\n");
        } else {
            for (ASN1Encodable asn1Encodable : instance) {
                parsedAsn1Ext.append(asn1Encodable).append("\n");
            }

        }
    }

    private static void parseSubjectKeyIdentifier(Localization localization,
                                                  Extension extension,
                                                  StringBuilder parsedAsn1Ext) {
        SubjectKeyIdentifier instance = SubjectKeyIdentifier.getInstance(extension.getParsedValue());
        parsedAsn1Ext.append(Hex.toHexString(instance.getKeyIdentifier()));
    }

    private static void parseKeyUsage(Localization localization, Extension extension, StringBuilder parsedAsn1Ext) {
        KeyUsage keyUsage = KeyUsage.getInstance(extension.getParsedValue());
        parsedAsn1Ext.append(keyUsage).append("\n\n");


        if (keyUsage.hasUsages(KeyUsage.digitalSignature))
            parsedAsn1Ext.append("Цифровая подпись").append("\n");
        if (keyUsage.hasUsages(KeyUsage.nonRepudiation))
            parsedAsn1Ext.append("Неотрекаемость").append("\n");
        if (keyUsage.hasUsages(KeyUsage.keyEncipherment))
            parsedAsn1Ext.append("Шифрование ключей").append("\n");
        if (keyUsage.hasUsages(KeyUsage.dataEncipherment))
            parsedAsn1Ext.append("Шифрование данных").append("\n");
        if (keyUsage.hasUsages(KeyUsage.keyAgreement))
            parsedAsn1Ext.append("Согласование ключей").append("\n");
        if (keyUsage.hasUsages(KeyUsage.keyCertSign))
            parsedAsn1Ext.append("Подписывание сертификатов").append("\n");
        if (keyUsage.hasUsages(KeyUsage.cRLSign))
            parsedAsn1Ext.append("Автономное подписание списка отзыва (CRL), Подписывание списка отзыва (CRL)")
                    .append("\n");
        if (keyUsage.hasUsages(KeyUsage.encipherOnly))
            parsedAsn1Ext.append("Только шифрование").append("\n");
        if (keyUsage.hasUsages(KeyUsage.decipherOnly))
            parsedAsn1Ext.append("Только расшифровка").append("\n");
    }

    private static void parseAuthorityKeyIdentifier(Localization localization,
                                                    Extension extension,
                                                    StringBuilder parsedAsn1Ext) {
        AuthorityKeyIdentifier instance = AuthorityKeyIdentifier.getInstance(extension.getParsedValue());
        if (instance.getKeyIdentifier() != null)
            parsedAsn1Ext.append("KeyIdentifier: \n\t")
                    .append(Hex.toHexString(instance.getKeyIdentifier()))
                    .append("\n");
        if (instance.getAuthorityCertSerialNumber() != null)
            parsedAsn1Ext.append("AuthorityCertSerialNumber: \n\t")
                    .append(instance.getAuthorityCertSerialNumber().toString(16))
                    .append("\n");
        if (instance.getAuthorityCertIssuer() != null) {
            parsedAsn1Ext.append("AuthorityCertIssuer: \n");
            for (GeneralName name : instance.getAuthorityCertIssuer().getNames()) {
                if (name.getName() instanceof X500Name x500Name) {
                    Map<String, String> convert = convert(x500Name);
                    for (Map.Entry<String, String> entry : convert.entrySet()) {
                        parsedAsn1Ext.append("\t").append(entry.getKey())
                                .append(" = ").append(entry.getValue()).append("\n");
                    }
                } else {
                    parsedAsn1Ext.append(name).append("\n");
                }
            }
        }
    }

    public static Map<String, String> convert(X500Name x500Name) {
        Map<String, String> map = new LinkedHashMap<>();
        RDN[] rdNs = x500Name.getRDNs();
        for (RDN rdn : rdNs) {
            String[]
                    names =
                    X500Name.getDefaultStyle()
                            .oidToAttrNames(new ASN1ObjectIdentifier(rdn.getFirst().getType().toString()));
            map.put(names.length > 0 ? names[0].toUpperCase() : rdn.getFirst().getType().toString(),
                    rdn.getFirst().getValue().toString());
        }
        return map;
    }
}
