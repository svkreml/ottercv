package svkreml.tsl.tsl;


import jakarta.xml.bind.annotation.*;
import javax.xml.datatype.XMLGregorianCalendar;


@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "ДанныеСертификатаТип")
public class CertData {

    @XmlElement(name = "\u041e\u0442\u043f\u0435\u0447\u0430\u0442\u043e\u043a", required = true)

    protected String thumbPrint;
    @XmlElement(name = "\u041a\u0435\u043c\u0412\u044b\u0434\u0430\u043d", required = true)

    protected String issuedBy;
    @XmlElement(name = "\u041a\u043e\u043c\u0443\u0412\u044b\u0434\u0430\u043d", required = true)

    protected String issuedTo;
    @XmlElement(name = "\u0421\u0435\u0440\u0438\u0439\u043d\u044b\u0439\u041d\u043e\u043c\u0435\u0440", required = true)

    protected String serial;
    @XmlElement(name = "\u041f\u0435\u0440\u0438\u043e\u0434\u0414\u0435\u0439\u0441\u0442\u0432\u0438\u044f\u0421", required = true)
    @XmlSchemaType(name = "dateTime")

    protected XMLGregorianCalendar dateFrom;
    @XmlElement(name = "\u041f\u0435\u0440\u0438\u043e\u0434\u0414\u0435\u0439\u0441\u0442\u0432\u0438\u044f\u0414\u043e", required = true)
    @XmlSchemaType(name = "dateTime")

    protected XMLGregorianCalendar dateTo;
    @XmlElement(name = "\u0414\u0430\u043d\u043d\u044b\u0435", required = true)

    protected byte[] rawCert;



    public String getThumbPrint() {
        return thumbPrint;
    }



    public void setThumbPrint(String value) {
        this.thumbPrint = value;
    }



    public String getIssuedBy() {
        return issuedBy;
    }



    public void setIssuedBy(String value) {
        this.issuedBy = value;
    }



    public String getIssuedTo() {
        return issuedTo;
    }



    public void setIssuedTo(String value) {
        this.issuedTo = value;
    }



    public String getSerial() {
        return serial;
    }


    public void setSerial(String value) {
        this.serial = value;
    }



    public XMLGregorianCalendar getDateFrom() {
        return dateFrom;
    }



    public void setDateFrom(XMLGregorianCalendar value) {
        this.dateFrom = value;
    }



    public XMLGregorianCalendar getDateTo() {
        return dateTo;
    }



    public void setDateTo(XMLGregorianCalendar value) {
        this.dateTo = value;
    }



    public byte[] getRawCert() {
        return rawCert;
    }



    public void setRawCert(byte[] value) {
        this.rawCert = value;
    }

}
