
package svkreml.tsl.tsl;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlType;


@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "\u0410\u0434\u0440\u0435\u0441\u0422\u0438\u043f")

public class Address {

    @XmlElement(name = "\u0421\u0442\u0440\u0430\u043d\u0430", required = true)

    protected String country;
    @XmlElement(name = "\u0420\u0435\u0433\u0438\u043e\u043d", required = true)

    protected Region region;
    @XmlElement(name = "\u0418\u043d\u0434\u0435\u043a\u0441", required = true)

    protected String postIndex;
    @XmlElement(name = "\u0423\u043b\u0438\u0446\u0430\u0414\u043e\u043c", required = true)

    protected String street;
    @XmlElement(name = "\u0413\u043e\u0440\u043e\u0434", required = true)

    protected String city;



    public String getCountry() {
        return country;
    }



    public void setCountry(String value) {
        this.country = value;
    }



    public Region getRegion() {
        return region;
    }



    public void setRegion(Region value) {
        this.region = value;
    }



    public String getPostIndex() {
        return postIndex;
    }



    public void setPostIndex(String value) {
        this.postIndex = value;
    }



    public String getStreet() {
        return street;
    }



    public void setStreet(String value) {
        this.street = value;
    }



    public String getCity() {
        return city;
    }



    public void setCity(String value) {
        this.city = value;
    }

}
