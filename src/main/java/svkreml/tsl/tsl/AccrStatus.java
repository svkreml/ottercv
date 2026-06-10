package svkreml.tsl.tsl;

import jakarta.xml.bind.annotation.*;

import javax.xml.datatype.XMLGregorianCalendar;


@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "\u0421\u0442\u0430\u0442\u0443\u0441\u0410\u043a\u043a\u0440\u0435\u0434\u0438\u0442\u0430\u0446" +
        "\u0438\u0438\u0422\u0438\u043f")

public class AccrStatus {

    @XmlElement(name = "\u0421\u0442\u0430\u0442\u0443\u0441", required = true)

    protected String status;
    @XmlElement(name = "\u0414\u0435\u0439\u0441\u0442\u0432\u0443\u0435\u0442\u0421", required = true)
    @XmlSchemaType(name = "dateTime")

    protected XMLGregorianCalendar dateFrom;

    public String getStatus() {
        return status;
    }

    public void setStatus(String value) {
        this.status = value;
    }

    public XMLGregorianCalendar getDateFrom() {
        return dateFrom;
    }

    public void setDateFrom(XMLGregorianCalendar value) {
        this.dateFrom = value;
    }

}
