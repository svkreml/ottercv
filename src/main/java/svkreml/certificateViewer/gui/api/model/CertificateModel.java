package svkreml.certificateViewer.gui.api.model;

import javafx.beans.property.Property;
import javafx.beans.property.SimpleObjectProperty;
import javafx.util.Pair;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.bouncycastle.cert.X509CertificateHolder;

import java.util.Date;
import java.util.List;
import java.util.Objects;

@Setter
@Getter
public class CertificateModel {

    public CertificateGeneralInfo certificateGeneralInfo;
    public List<CertificateDetail> certificateDetails;
    public Property<List<CertificateChain>> certificateChain = new SimpleObjectProperty<>();

    public CertificateModel(CertificateGeneralInfo certificateGeneralInfo, List<CertificateDetail> certificateDetails) {
        this.certificateGeneralInfo = certificateGeneralInfo;
        this.certificateDetails = certificateDetails;
    }

    @Setter
    @Getter
    public static class CertificateGeneralInfo {
        public Property<CertificateStatus> certificateStatus = new SimpleObjectProperty<>();
        public Property<List<String>> statusDetails = new SimpleObjectProperty<>();
        public String issuedBy;
        public String issuedTo;
        public Date validFrom;
        public Date validTo;

        public CertificateGeneralInfo(String issuedBy, String issuedTo, Date validFrom, Date validTo) {
            this.issuedBy = issuedBy;
            this.issuedTo = issuedTo;
            this.validFrom = validFrom;
            this.validTo = validTo;
        }

        public CertificateGeneralInfo(Property<CertificateStatus> certificateStatus,
                                      Property<List<String>> statusDetails,
                                      String issuedBy,
                                      String issuedTo,
                                      Date validFrom,
                                      Date validTo) {
            this.certificateStatus = certificateStatus;
            this.statusDetails = statusDetails;
            this.issuedBy = issuedBy;
            this.issuedTo = issuedTo;
            this.validFrom = validFrom;
            this.validTo = validTo;
        }

    }

    @Setter
    @Getter
    @NoArgsConstructor
    public static class CertificateDetail {
        String field;
        String value;
        String detail;
        DetailType detailType;

        public CertificateDetail(String field, String value, String detail, DetailType detailType) {
            this.field = field;
            this.value = value;
            this.detail = detail;
            this.detailType = detailType;
        }

        public Pair<String, DetailType> getFieldWithType() {
            return new Pair<>(field, detailType);
        }

        public String getValueOneLine() {
            return value.replaceAll("([\t ]+)", " ").replaceAll("([\r\n])+", ", ").trim();
        }

    }

    @Setter
    @Getter
    @NoArgsConstructor
    public static class CertificateChain {
        public String cn;
        public CertificateStatus certificateStatus;
        public X509CertificateHolder x509CertificateHolder;
        public List<String> list;
        public CertificateChain(String cn,
                                CertificateStatus certificateStatus,
                                X509CertificateHolder x509CertificateHolder,
                                List<String> list) {
            this.cn = cn;
            this.certificateStatus = certificateStatus;
            this.x509CertificateHolder = x509CertificateHolder;
            this.list = list;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            CertificateChain that = (CertificateChain) o;
            return Objects.equals(getCn(), that.getCn()) &&
                    getCertificateStatus() == that.getCertificateStatus() &&
                    Objects.equals(getX509CertificateHolder(), that.getX509CertificateHolder()) &&
                    Objects.equals(getList(), that.getList());
        }

        @Override
        public int hashCode() {
            return Objects.hash(getCn(), getCertificateStatus(), getX509CertificateHolder(), getList());
        }

        @Override
        public String toString() {
            return cn;
        }

    }
}
