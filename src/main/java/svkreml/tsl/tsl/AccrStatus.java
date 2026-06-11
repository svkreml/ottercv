package svkreml.tsl.tsl;

import jakarta.xml.bind.annotation.*;
import lombok.Getter;
import lombok.Setter;

import javax.xml.datatype.XMLGregorianCalendar;


@Setter
@Getter
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "СтатусАккредитацииТип")
public class AccrStatus {

    @XmlElement(name = "Статус", required = true)

    protected String status;
    @XmlElement(name = "ДействуетС", required = true)
    @XmlSchemaType(name = "dateTime")
    protected XMLGregorianCalendar dateFrom;

}
