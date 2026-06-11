package svkreml.tsl.tsl;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlType;
import lombok.Getter;
import lombok.Setter;

import java.math.BigInteger;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "РегионТип")
@Setter
@Getter
public class Region {

    @XmlElement(name = "Код", required = true)

    protected BigInteger code;
    @XmlElement(name = "Название", required = true)

    protected String name;

}
