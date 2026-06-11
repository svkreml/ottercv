package svkreml.tsl.tsl;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlType;
import lombok.Getter;
import lombok.Setter;

@Setter @Getter
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "АдресТип")
public class Address {

    @XmlElement(name = "Страна", required = true)

    protected String country;
    @XmlElement(name = "Регион", required = true)

    protected Region region;
    @XmlElement(name = "Индекс", required = true)

    protected String postIndex;
    @XmlElement(name = "УлицаДом", required = true)

    protected String street;
    @XmlElement(name = "Город", required = true)

    protected String city;

}
