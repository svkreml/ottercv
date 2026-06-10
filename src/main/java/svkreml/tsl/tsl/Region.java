package svkreml.tsl.tsl;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlType;

import java.math.BigInteger;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "\u0420\u0435\u0433\u0438\u043e\u043d\u0422\u0438\u043f")
public class Region {

    @XmlElement(name = "\u041a\u043e\u0434", required = true)

    protected BigInteger code;
    @XmlElement(name = "\u041d\u0430\u0437\u0432\u0430\u043d\u0438\u0435", required = true)

    protected String name;

    public BigInteger getCode() {
        return code;
    }

    public void setCode(BigInteger value) {
        this.code = value;
    }

    public String getName() {
        return name;
    }

    public void setName(String value) {
        this.name = value;
    }

}
