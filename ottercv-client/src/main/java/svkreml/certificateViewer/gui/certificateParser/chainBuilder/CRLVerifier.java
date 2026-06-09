package svkreml.certificateViewer.gui.certificateParser.chainBuilder;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.*;
import svkreml.certificateViewer.gui.view.utils.WebUtils;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.*;
import java.util.*;


public class CRLVerifier {

    static HashMap<X509Certificate, X509CRL> cachedCrl = new HashMap<>();

    public static void verifyCertificateCRLs(X509Certificate cert, PKIXCertPathBuilderResult verifiedCertChain)
            throws CertificateVerificationException {
        try {
            X509CRL crl = cachedCrl.get(cert);
            if (crl == null || crl.getNextUpdate().before(new Date())) {
                List<String> crlDistPoints = getCrlDistributionPoints(cert);
                for (String crlDP : crlDistPoints) {
                    try {
                        System.out.println("Качаем CRL: " + crlDP);
                        try (InputStream crlStream = WebUtils.download(crlDP)) {
                            CertificateFactory cf = CertificateFactory.getInstance("X.509");
                            crl = (X509CRL) cf.generateCRL(crlStream);
                        }
                        List<? extends Certificate> certificates = verifiedCertChain.getCertPath().getCertificates();
                        if (certificates.size() <= 1)
                            crl.verify(verifiedCertChain.getTrustAnchor().getTrustedCert().getPublicKey(), "BC");
                        else
                            crl.verify(certificates.get(certificates.size() - 1).getPublicKey(), "BC");
                        cachedCrl.putIfAbsent(cert, crl);
                        break;
                    } catch (Exception e){
                        e.printStackTrace();
                    }
                }
            }
            if (Objects.requireNonNull(crl).isRevoked(cert)) {
                throw new CertificateVerificationException(
                        "The certificate is revoked by CRL: " + crl);
            }
        } catch (Exception ex) {
            if (ex instanceof CertificateVerificationException) {
                throw (CertificateVerificationException) ex;
            } else {
                throw new CertificateVerificationException(
                        "Can not verify CRL for certificate: " +
                                cert.getSubjectX500Principal());
            }
        }
    }



    public static List<String> getCrlDistributionPoints(
            X509Certificate cert) throws CertificateParsingException, IOException {
        byte[] crldpExt = cert.getExtensionValue(
                Extension.cRLDistributionPoints.getId());
        if (crldpExt == null) {
            return new ArrayList<>();
        }
        ASN1InputStream oAsnInStream = new ASN1InputStream(
                new ByteArrayInputStream(crldpExt));
        ASN1Primitive derObjCrlDP = oAsnInStream.readObject();
        DEROctetString dosCrlDP = (DEROctetString) derObjCrlDP;
        byte[] crldpExtOctets = dosCrlDP.getOctets();
        ASN1InputStream oAsnInStream2 = new ASN1InputStream(
                new ByteArrayInputStream(crldpExtOctets));
        ASN1Primitive derObj2 = oAsnInStream2.readObject();
        CRLDistPoint distPoint = CRLDistPoint.getInstance(derObj2);
        List<String> crlUrls = new ArrayList<String>();
        for (DistributionPoint dp : distPoint.getDistributionPoints()) {
            DistributionPointName dpn = dp.getDistributionPoint();
            if (dpn != null) {
                if (dpn.getType() == DistributionPointName.FULL_NAME) {
                    GeneralName[] genNames = GeneralNames.getInstance(
                            dpn.getName()).getNames();
                    for (GeneralName genName : genNames) {
                        if (genName.getTagNo() == GeneralName.uniformResourceIdentifier) {
                            String url = DERIA5String.getInstance(
                                    genName.getName()).getString();
                            crlUrls.add(url);
                        }
                    }
                }
            }
        }
        return crlUrls;
    }

}

