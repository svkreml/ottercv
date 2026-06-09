package svkreml.certificateViewer.gui.certificateParser;


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
import java.security.cert.X509Certificate;
import java.util.*;

public class CertificateParser {
    static {
        if (!(X500Name.getDefaultStyle() instanceof CustomBCStyle)) {
            X500Name.setDefaultStyle(new CustomBCStyle());
        }
    }

    public static CertificateModel getCertificateModel(Localization localization, X509CertificateHolder x509CertificateHolder) throws Exception {

        //x509CertificateHolder.getIssuer();

        Map<ASN1ObjectIdentifier, String> issuer = x500NameToMap(x509CertificateHolder.getIssuer());
        Map<ASN1ObjectIdentifier, String> subject = x500NameToMap(x509CertificateHolder.getSubject());


        CertificateModel.CertificateGeneralInfo certificateGeneralInfo = new CertificateModel.CertificateGeneralInfo(
                issuer.get(X500Name.getDefaultStyle().attrNameToOID("CN")),
                subject.get(X500Name.getDefaultStyle().attrNameToOID("CN")),
                x509CertificateHolder.getNotBefore(),
                x509CertificateHolder.getNotAfter()
        );


        //   certificateDetails.add(new CertificateModel.CertificateDetail("Алгоритма хэша подписи",localization.getIssuerSignatureType(x509CertificateHolder.getEncoded()), null, DetailType.PROP));

        List<CertificateModel.CertificateDetail> certificateDetails = new ArrayList<>();
        certificateDetails.add(new CertificateModel.CertificateDetail(localization.TAB_DETAIL_TABLE_KEY_VERSION, "V" + (x509CertificateHolder.getVersionNumber()), null, DetailType.PROP));
        certificateDetails.add(new CertificateModel.CertificateDetail(localization.TAB_DETAIL_TABLE_KEY_SERIAL_NUMBER, x509CertificateHolder.getSerialNumber().toString(16), null, DetailType.PROP));
        certificateDetails.add(new CertificateModel.CertificateDetail(localization.TAB_DETAIL_TABLE_KEY_ALG, localization.convertOidToString(x509CertificateHolder.getSignatureAlgorithm().getAlgorithm()), null, DetailType.PROP));
        certificateDetails.add(new CertificateModel.CertificateDetail(localization.TAB_DETAIL_TABLE_KEY_ISSUER, parseX500ToTextArea(issuer), null, DetailType.PROP));
        certificateDetails.add(new CertificateModel.CertificateDetail(localization.TAB_DETAIL_TABLE_KEY_VALID_FROM, localization.formatDate(certificateGeneralInfo.getValidFrom()), null, DetailType.PROP));
        certificateDetails.add(new CertificateModel.CertificateDetail(localization.TAB_DETAIL_TABLE_KEY_VALID_UNTIL, localization.formatDate(certificateGeneralInfo.getValidTo()), null, DetailType.PROP));
        certificateDetails.add(new CertificateModel.CertificateDetail(localization.TAB_DETAIL_TABLE_KEY_SUBJECT, parseX500ToTextArea(subject), null, DetailType.PROP));

        //   AsymmetricKeyParameter publicKey = KeyFactory.createKey();

        certificateDetails.add(new CertificateModel.CertificateDetail(localization.TAB_DETAIL_TABLE_KEY_PUBLIC_KEY,
                localization.convertOidToString(x509CertificateHolder.getSubjectPublicKeyInfo().getAlgorithm().getAlgorithm())
                , x509CertificateHolder.getSubjectPublicKeyInfo().getPublicKeyData().getString().substring(1)
                , DetailType.PROP));

        KeyInfo keyInfo = KeyParser.getKeyInfo(KeyParser.loadCertificate(x509CertificateHolder.getEncoded()).getPublicKey());
        //  if(keyInfo.getAlgorithm().equals("RSA"))
        certificateDetails.add(new CertificateModel.CertificateDetail(localization.TAB_DETAIL_TABLE_KEY_PUBLIC_KEY_DETAILS,
                localization.TAB_DETAIL_TABLE_KEY_PUBLIC_KEY_LENGTH + " " + keyInfo.getSize()
                        + "\n" + localization.TAB_DETAIL_TABLE_KEY_PUBLIC_KEY_ALG + " " + keyInfo.getAlgorithm() + ""
                        + "\n" + localization.TAB_DETAIL_TABLE_KEY_PUBLIC_KEY_PARAMS + " " + keyInfo.getDetailedAlgorithm() +
                        ((keyInfo.getExponent() != null) ? ("\n" + localization.TAB_DETAIL_TABLE_KEY_PUBLIC_KEY_RSA_EXP + " " + keyInfo.getExponent()) : "")
                , null
                , DetailType.PROP));

        for (Object extensionOID : x509CertificateHolder.getExtensionOIDs()) {
            Extension extension = x509CertificateHolder.getExtension((ASN1ObjectIdentifier) extensionOID);
            try {
                certificateDetails.add(ExtensionParser.parseExtension(localization, extension));
            } catch (Exception e) {
                try {
                    certificateDetails.add(new CertificateModel.CertificateDetail(
                            localization.convertOidToString(extension.getExtnId()) + ", " + extension.getExtnId().getId(),
                            e.getMessage(),
                            extension.getParsedValue().toString(),
                            extension.isCritical() ? DetailType.CRIT_EXT : DetailType.NON_CRIT_EXT)
                    );
                    e.printStackTrace();
                } catch (Exception ex) {
                    certificateDetails.add(new CertificateModel.CertificateDetail(
                            localization.convertOidToString(extension.getExtnId()) + ", " + extension.getExtnId().getId(),
                            e.getMessage(),
                            null,
                            extension.isCritical() ? DetailType.CRIT_EXT : DetailType.NON_CRIT_EXT)
                    );
                    ex.printStackTrace();
                }
            }
        }


        certificateDetails.add(new CertificateModel.CertificateDetail(localization.TAB_DETAIL_TABLE_KEY_THUMBPRINT_ALG, "SHA1", null, DetailType.THUMBPRINT));
        certificateDetails.add(new CertificateModel.CertificateDetail(localization.TAB_DETAIL_TABLE_KEY_THUMBPRINT_VALUE, getThumbprintSha1(x509CertificateHolder.getEncoded()), null, DetailType.THUMBPRINT));

        certificateDetails.add(new CertificateModel.CertificateDetail(localization.TAB_DETAIL_TABLE_KEY_THUMBPRINT_ALG, "SHA256", null, DetailType.THUMBPRINT));
        certificateDetails.add(new CertificateModel.CertificateDetail(localization.TAB_DETAIL_TABLE_KEY_THUMBPRINT_VALUE, getThumbprintSha256(x509CertificateHolder.getEncoded()), null, DetailType.THUMBPRINT));


        CertificateModel certificateModel = new CertificateModel(certificateGeneralInfo, certificateDetails);

        return certificateModel;
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

    public static void validateCertificate(Localization localization, X509CertificateHolder x509CertificateHolder, CertificateModel сertificateModel) throws CertificateException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, IOException {

    }


    public static class Validate {
        public Localization getLocalization() {
            return localization;
        }

        public Validate setLocalization(Localization localization) {
            this.localization = localization;
            return this;
        }

        public X509CertificateHolder getX509CertificateHolder() {
            return x509CertificateHolder;
        }

        public Validate setX509CertificateHolder(X509CertificateHolder x509CertificateHolder) {
            this.x509CertificateHolder = x509CertificateHolder;
            return this;
        }

        public List<String> getVerificationDetails() {
            return verificationDetails;
        }

        public Validate setVerificationDetails(List<String> verificationDetails) {
            this.verificationDetails = verificationDetails;
            return this;
        }

        public CertificateStatus getCertificateStatus() {
            return certificateStatus;
        }

        public Validate setCertificateStatus(CertificateStatus certificateStatus) {
            this.certificateStatus = certificateStatus;
            return this;
        }

        public ArrayList<CertificateModel.CertificateChain> getCertificateChains() {
            return certificateChains;
        }

        public Validate setCertificateChains(ArrayList<CertificateModel.CertificateChain> certificateChains) {
            this.certificateChains = certificateChains;
            return this;
        }

        private Localization localization;
        private X509CertificateHolder x509CertificateHolder;
        private List<String> verificationDetails;
        private CertificateStatus certificateStatus;
        private ArrayList<CertificateModel.CertificateChain> certificateChains;

        public Validate(Localization localization, X509CertificateHolder x509CertificateHolder) {
            this.localization = localization;
            this.x509CertificateHolder = x509CertificateHolder;
        }

        private static CertificateStatus getCertificateStatus(X509CertificateHolder x509CertificateHolder, List<String> verificationDetails, CertificateVerifier certificateVerifier) {
            CertificateStatus certificateStatus = CertificateStatus.UNKNOWN;
            try {
                certificateVerifier.verifyCertificate(KeyParser.loadCertificate(x509CertificateHolder.getEncoded()));
                if (verificationDetails != null) verificationDetails.add("Сертификат находится в TSL");
                certificateStatus = CertificateStatus.TRUSTED;
            } catch (Exception e) {
                //  e.printStackTrace();
                if (verificationDetails != null) verificationDetails.add(e.getMessage());
                Throwable cause = e.getCause();
                while (cause != null) {
                    if (verificationDetails != null) verificationDetails.add(cause.getMessage());
                    cause = cause.getCause();
                }
                certificateStatus = CertificateStatus.BROKEN;
            }
            return certificateStatus;
        }

        public Validate invoke() throws CertificateException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, IOException {
            verificationDetails = new ArrayList<>();
            Set<X509Certificate> gostTlsStore = null;
            try {
                gostTlsStore = TrustChainBuilder.smallInit(localization, x509CertificateHolder);
                //  gostTlsStore = TrustChainBuilder.gostTlsStore();
            } catch (Exception e) {
                e.printStackTrace();
                verificationDetails.add(e.getMessage());
                gostTlsStore = new HashSet<>();
            }
            certificateChains = new ArrayList<>();
            Map<ASN1ObjectIdentifier, String> subject = x500NameToMap(x509CertificateHolder.getSubject());


            if (!gostTlsStore.isEmpty()) {
                CertificateVerifier certificateVerifier = new CertificateVerifier(gostTlsStore);
                certificateStatus = getCertificateStatus(x509CertificateHolder, verificationDetails, certificateVerifier);


                certificateChains.add(new CertificateModel.CertificateChain(
                        subject.get(X500Name.getDefaultStyle().attrNameToOID("CN")),
                        certificateStatus, x509CertificateHolder, verificationDetails));
                for (X509Certificate x509Certificate : gostTlsStore) {
                    X509CertificateHolder x509CertificateHolder1 = new X509CertificateHolder(x509Certificate.getEncoded());
                    List<String> verificationDetails1 = new ArrayList<>();
                    certificateChains.add(new CertificateModel.CertificateChain(
                            x500NameToMap(x509CertificateHolder1.getSubject()).get(X500Name.getDefaultStyle().attrNameToOID("CN")),
                            getCertificateStatus(x509CertificateHolder1, verificationDetails1, certificateVerifier),
                            x509CertificateHolder1, verificationDetails1));
                }
            } else {
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
                            x500NameToMap(x509CertificateHolder1.getSubject()).get(X500Name.getDefaultStyle().attrNameToOID("CN")),
                            CertificateStatus.UNTRUSTED_ROOT,
                            x509CertificateHolder1, verificationDetails1));
                    x509CertificateHolder = x509CertificateHolder1;
                }
            }

            return this;
        }

        private X509CertificateHolder getCa(X509CertificateHolder x509CertificateHolder) {
            try {
                AuthorityInformationAccess instance = AuthorityInformationAccess.fromExtensions(x509CertificateHolder.getExtensions());
                if (instance == null) return null;
                for (AccessDescription accessDescription : instance.getAccessDescriptions()) {
                    if (accessDescription.getAccessMethod().getId().equals("1.3.6.1.5.5.7.48.2")) {
                        byte[] bytes = Streams.readAllLimited(WebUtils.download(accessDescription.getAccessLocation().toASN1Primitive().toString().split("]", 2)[1]), 20000);
                        return new X509CertificateHolder(Utils.clearCertBytes(bytes));
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
            return null;
        }
    }


}
