package svkreml.certificateViewer.gui.api.model;

import javafx.beans.property.Property;
import javafx.beans.property.SimpleObjectProperty;
import javafx.util.Pair;
import org.bouncycastle.cert.X509CertificateHolder;

import java.util.Date;
import java.util.List;

public class CertificateModel {

    public CertificateGeneralInfo certificateGeneralInfo;
    public List<CertificateDetail> certificateDetails;
    public Property<List<CertificateChain>> certificateChain = new SimpleObjectProperty<>();

    public CertificateModel(CertificateGeneralInfo certificateGeneralInfo, List<CertificateDetail> certificateDetails) {
        this.certificateGeneralInfo = certificateGeneralInfo;
        this.certificateDetails = certificateDetails;
    }

    public CertificateModel(CertificateGeneralInfo certificateGeneralInfo, List<CertificateDetail> certificateDetails, Property<List<CertificateChain>> certificateChain) {
        this.certificateGeneralInfo = certificateGeneralInfo;
        this.certificateDetails = certificateDetails;
        this.certificateChain = certificateChain;
    }

    public CertificateGeneralInfo getCertificateGeneralInfo() {
        return this.certificateGeneralInfo;
    }

    public List<CertificateDetail> getCertificateDetails() {
        return this.certificateDetails;
    }

    public Property<List<CertificateChain>> getCertificateChain() {
        return this.certificateChain;
    }

    public void setCertificateGeneralInfo(CertificateGeneralInfo certificateGeneralInfo) {
        this.certificateGeneralInfo = certificateGeneralInfo;
    }

    public void setCertificateDetails(List<CertificateDetail> certificateDetails) {
        this.certificateDetails = certificateDetails;
    }

    public void setCertificateChain(Property<List<CertificateChain>> certificateChain) {
        this.certificateChain = certificateChain;
    }

    ;


/*
    public CertificateModel testData() {
        return testData(3);
    }
    private CertificateModel testData(int selfSigned) {
        certificateGeneralInfo = new CertificateGeneralInfo().testData();
        certificateDetails = Arrays.asList(new CertificateDetail().testData(), new CertificateDetail().testData());



        if (selfSigned == 0) {
            this.certificateGeneralInfo.issuedTo = "ROOT";
            this.certificateGeneralInfo.issuedBy = "ROOT";
            certificateChain = new CertificateChain().testData(null);
        } else {
            --selfSigned;
            CertificateModel root = new CertificateModel().testData(selfSigned);
            root.certificateGeneralInfo.issuedTo = "SUB"+selfSigned;
            root.certificateGeneralInfo.certificateStatus = CertificateStatus.OVERDUE;
            certificateChain = new CertificateChain().testData(root);

        }
        return this;
    }
*/

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

        public CertificateGeneralInfo(Property<CertificateStatus> certificateStatus, Property<List<String>> statusDetails, String issuedBy, String issuedTo, Date validFrom, Date validTo) {
            this.certificateStatus = certificateStatus;
            this.statusDetails = statusDetails;
            this.issuedBy = issuedBy;
            this.issuedTo = issuedTo;
            this.validFrom = validFrom;
            this.validTo = validTo;
        }

        public Property<CertificateStatus> getCertificateStatus() {
            return this.certificateStatus;
        }

        public Property<List<String>> getStatusDetails() {
            return this.statusDetails;
        }

        public String getIssuedBy() {
            return this.issuedBy;
        }

        public String getIssuedTo() {
            return this.issuedTo;
        }

        public Date getValidFrom() {
            return this.validFrom;
        }

        public Date getValidTo() {
            return this.validTo;
        }

        public void setCertificateStatus(Property<CertificateStatus> certificateStatus) {
            this.certificateStatus = certificateStatus;
        }

        public void setStatusDetails(Property<List<String>> statusDetails) {
            this.statusDetails = statusDetails;
        }

        public void setIssuedBy(String issuedBy) {
            this.issuedBy = issuedBy;
        }

        public void setIssuedTo(String issuedTo) {
            this.issuedTo = issuedTo;
        }

        public void setValidFrom(Date validFrom) {
            this.validFrom = validFrom;
        }

        public void setValidTo(Date validTo) {
            this.validTo = validTo;
        }
/*        @Override
        public String toString() {
            return issuedTo;
        }*/
    }

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

        public CertificateDetail() {
        }

        public Pair<String, DetailType> getFieldWithType() {
            return new Pair<>(field, detailType);
        }

        public String getValueOneLine() {
            return value.replaceAll("([\t ]+)", " ").replaceAll("([\r\n])+", ", ").trim();
        }

        public String getField() {
            return this.field;
        }

        public String getValue() {
            return this.value;
        }

        public String getDetail() {
            return this.detail;
        }

        public DetailType getDetailType() {
            return this.detailType;
        }

        public void setField(String field) {
            this.field = field;
        }

        public void setValue(String value) {
            this.value = value;
        }

        public void setDetail(String detail) {
            this.detail = detail;
        }

        public void setDetailType(DetailType detailType) {
            this.detailType = detailType;
        }
    }


    public static class CertificateChain {
        public String cn;
        public CertificateStatus certificateStatus;
        public X509CertificateHolder x509CertificateHolder;
        public List<String> list;

        public CertificateChain(String cn, CertificateStatus certificateStatus, X509CertificateHolder x509CertificateHolder, List<String> list) {
            this.cn = cn;
            this.certificateStatus = certificateStatus;
            this.x509CertificateHolder = x509CertificateHolder;
            this.list = list;
        }

        public CertificateChain() {
        }

        @Override
        public String toString() {
            return cn;
        }

        public String getCn() {
            return this.cn;
        }

        public CertificateStatus getCertificateStatus() {
            return this.certificateStatus;
        }

        public X509CertificateHolder getX509CertificateHolder() {
            return this.x509CertificateHolder;
        }

        public List<String> getList() {
            return this.list;
        }

        public void setCn(String cn) {
            this.cn = cn;
        }

        public void setCertificateStatus(CertificateStatus certificateStatus) {
            this.certificateStatus = certificateStatus;
        }

        public void setX509CertificateHolder(X509CertificateHolder x509CertificateHolder) {
            this.x509CertificateHolder = x509CertificateHolder;
        }

        public void setList(List<String> list) {
            this.list = list;
        }
    }
}
