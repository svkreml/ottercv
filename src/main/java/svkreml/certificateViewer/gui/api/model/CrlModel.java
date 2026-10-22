package svkreml.certificateViewer.gui.api.model;

import javafx.beans.property.Property;
import javafx.beans.property.SimpleObjectProperty;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.bouncycastle.cert.X509CRLHolder;

import java.util.Date;
import java.util.List;

@Getter
@Setter
public class CrlModel {

    private CrlGeneralInfo generalInfo;
    private List<CertificateModel.CertificateDetail> details;
    private List<RevokedCertificate> revokedCertificates;
    private X509CRLHolder crlHolder;

    public CrlModel(CrlGeneralInfo generalInfo,
                    List<CertificateModel.CertificateDetail> details,
                    List<RevokedCertificate> revokedCertificates,
                    X509CRLHolder crlHolder) {
        this.generalInfo = generalInfo;
        this.details = details;
        this.revokedCertificates = revokedCertificates;
        this.crlHolder = crlHolder;
    }

    @Getter
    @Setter
    public static class CrlGeneralInfo {
        private Property<CrlStatus> status = new SimpleObjectProperty<>(CrlStatus.UNKNOWN);
        private Property<List<String>> statusDetails = new SimpleObjectProperty<>(List.of());
        private String issuer;
        private String issuerFull;
        private Date thisUpdate;
        private Date nextUpdate;
        private String version;
        private String signatureAlgorithm;
        private String crlNumber;
        private int revokedCount;

        public CrlGeneralInfo(String issuer,
                              String issuerFull,
                              Date thisUpdate,
                              Date nextUpdate,
                              String version,
                              String signatureAlgorithm,
                              String crlNumber,
                              int revokedCount) {
            this.issuer = issuer;
            this.issuerFull = issuerFull;
            this.thisUpdate = thisUpdate;
            this.nextUpdate = nextUpdate;
            this.version = version;
            this.signatureAlgorithm = signatureAlgorithm;
            this.crlNumber = crlNumber;
            this.revokedCount = revokedCount;
        }
    }

    @Getter
    @Setter
    @NoArgsConstructor
    public static class RevokedCertificate {
        private String serialNumber;
        private Date revocationDate;
        private String reason;
        private String certificateIssuer;
        private List<CertificateModel.CertificateDetail> details;

        public RevokedCertificate(String serialNumber,
                                  Date revocationDate,
                                  String reason,
                                  String certificateIssuer,
                                  List<CertificateModel.CertificateDetail> details) {
            this.serialNumber = serialNumber;
            this.revocationDate = revocationDate;
            this.reason = reason;
            this.certificateIssuer = certificateIssuer;
            this.details = details;
        }
    }
}
