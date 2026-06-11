package svkreml.tsl.tsl;


import jakarta.xml.bind.annotation.*;
import lombok.Getter;
import lombok.Setter;

import javax.xml.datatype.XMLGregorianCalendar;


@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "ДанныеСертификатаТип")
@Getter
@Setter
public class CertData {

    @XmlElement(name = "Отпечаток", required = true)

    protected String thumbPrint;
    @XmlElement(name = "КемВыдан", required = true)

    protected String issuedBy;
    @XmlElement(name = "КомуВыдан", required = true)

    protected String issuedTo;
    @XmlElement(name = "СерийныйНомер",
            required = true)

    protected String serial;
    @XmlElement(name = "ПериодДействияС",
            required = true)
    @XmlSchemaType(name = "dateTime")

    protected XMLGregorianCalendar dateFrom;
    @XmlElement(name = "ПериодДействияДо",
            required = true)
    @XmlSchemaType(name = "dateTime")

    protected XMLGregorianCalendar dateTo;
    @XmlElement(name = "Данные", required = true)

    protected byte[] rawCert;

}
