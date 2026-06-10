package svkreml.tsl.tsl;


import jakarta.xml.bind.annotation.*;

import javax.xml.datatype.XMLGregorianCalendar;
import java.util.ArrayList;
import java.util.List;


@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "АккредитованныеУдостоверяющиеЦентры")
@XmlRootElement(name = "\u0410\u043a\u043a\u0440\u0435\u0434\u0438\u0442\u043e\u0432\u0430\u043d\u043d\u044b\u0435" +
        "\u0423\u0434\u043e\u0441\u0442\u043e\u0432\u0435\u0440\u044f\u044e\u0449\u0438\u0435\u0426\u0435\u043d\u0442" +
        "\u0440\u044b")

public class ACA {

    @XmlElement(name = "\u0412\u0435\u0440\u0441\u0438\u044f")

    protected int version;
    @XmlElement(name = "\u0414\u0430\u0442\u0430", required = true)
    @XmlSchemaType(name = "dateTime")

    protected XMLGregorianCalendar date;
    @XmlElement(name = "\u0423\u0434\u043e\u0441\u0442\u043e\u0432\u0435\u0440\u044f\u044e\u0449\u0438\u0439\u0426" +
            "\u0435\u043d\u0442\u0440")

    protected List<CA> CA;

    public int getVersion() {
        return version;
    }

    public void setVersion(int value) {
        this.version = value;
    }

    public XMLGregorianCalendar getDate() {
        return date;
    }

    public void setDate(XMLGregorianCalendar value) {
        this.date = value;
    }

    public List<CA> getCA() {
        if (CA == null) {
            CA = new ArrayList<CA>();
        }
        return this.CA;
    }

    @XmlAccessorType(XmlAccessType.FIELD)
    @XmlType(name = "CA")

    public static class CA {

        @XmlElement(name = "\u041d\u0430\u0437\u0432\u0430\u043d\u0438\u0435", required = true)

        protected String name;
        @XmlElement(name = "\u042d\u043b\u0435\u043a\u0442\u0440\u043e\u043d\u043d\u0430\u044f\u041f\u043e\u0447" +
                "\u0442\u0430",
                required = true)

        protected String email;
        @XmlElement(name = "\u041a\u0440\u0430\u0442\u043a\u043e\u0435\u041d\u0430\u0437\u0432\u0430\u043d\u0438\u0435",
                required = true)

        protected String shortName;
        @XmlElement(name = "\u0410\u0434\u0440\u0435\u0441\u0421\u0418\u043d\u0444\u043e\u0440\u043c\u0430\u0446" +
                "\u0438\u0435\u0439\u041f\u043e\u0423\u0426",
                required = true)

        protected String caInfoUrl;
        @XmlElement(name = "\u0410\u0434\u0440\u0435\u0441\u0421\u0418\u043d\u0444\u043e\u0440\u043c\u0430\u0446" +
                "\u0438\u0435\u0439\u041f\u043e\u0420\u0435\u0435\u0441\u0442\u0440\u0430\u043c\u0421\u0435\u0440" +
                "\u0442\u0438\u0444\u0438\u043a\u0430\u0442\u043e\u0432")

        protected String anotherUrl;
        @XmlElement(name = "\u0410\u0434\u0440\u0435\u0441", required = true)

        protected Address address;
        @XmlElement(name = "\u041f\u0440\u043e\u0433\u0440\u0430\u043c\u043c\u043d\u043e\u0410\u043f\u043f\u0430" +
                "\u0440\u0430\u0442\u043d\u044b\u0435\u041a\u043e\u043c\u043f\u043b\u0435\u043a\u0441\u044b",
                required = true)

        protected PAKs PAKs;
        @XmlElement(name = "\u0418\u041d\u041d", required = true)

        protected String inn;
        @XmlElement(name = "\u041e\u0413\u0420\u041d", required = true)

        protected String ogrn;
        @XmlElement(name = "\u0420\u0435\u0435\u0441\u0442\u0440\u043e\u0432\u044b\u0439\u041d\u043e\u043c\u0435\u0440")

        protected int regNumber;
        @XmlElement(name = "\u0421\u0442\u0430\u0442\u0443\u0441\u0410\u043a\u043a\u0440\u0435\u0434\u0438\u0442" +
                "\u0430\u0446\u0438\u0438",
                required = true)

        protected AccrStatus accrStatus;
        @XmlElement(name = "\u0418\u0441\u0442\u043e\u0440\u0438\u044f\u0421\u0442\u0430\u0442\u0443\u0441\u043e" +
                "\u0432\u0410\u043a\u043a\u0440\u0435\u0434\u0438\u0442\u0430\u0446\u0438\u0438",
                required = true)

        protected AccredHistory accredHistory;
        @XmlElement(name = "\u041f\u043e\u043b\u043d\u043e\u043c\u043e\u0447\u0438\u044f\u041f\u0435\u0440\u0435" +
                "\u0434\u0430\u043d\u044b\u0423\u0426\u0441\u041e\u0413\u0420\u041d")

        protected Object wtf;

        public String getName() {
            return name;
        }

        public void setName(String value) {
            this.name = value;
        }

        public String getEmail() {
            return email;
        }

        public void setEmail(String value) {
            this.email = value;
        }

        public String getShortName() {
            return shortName;
        }

        public void setShortName(String value) {
            this.shortName = value;
        }

        public String getCaInfoUrl() {
            return caInfoUrl;
        }

        public void setCaInfoUrl(String value) {
            this.caInfoUrl = value;
        }

        public String getAnotherUrl() {
            return anotherUrl;
        }

        public void setAnotherUrl(String value) {
            this.anotherUrl = value;
        }

        public Address getAddress() {
            return address;
        }

        public void setAddress(Address value) {
            this.address = value;
        }

        public PAKs getPAKs() {
            return PAKs;
        }

        public void setPAKs(PAKs value) {
            this.PAKs = value;
        }

        public String getInn() {
            return inn;
        }

        public void setInn(String value) {
            this.inn = value;
        }

        public String getОГРН() {
            return ogrn;
        }

        public void setОГРН(String value) {
            this.ogrn = value;
        }

        public int getRegNumber() {
            return regNumber;
        }

        public void setRegNumber(int value) {
            this.regNumber = value;
        }

        public AccrStatus getAccrStatus() {
            return accrStatus;
        }

        public void setAccrStatus(AccrStatus value) {
            this.accrStatus = value;
        }

        public AccredHistory getAccredHistory() {
            return accredHistory;
        }

        public void setAccredHistory(AccredHistory value) {
            this.accredHistory = value;
        }

        public Object getWtf() {
            return wtf;
        }

        public void setWtf(Object value) {
            this.wtf = value;
        }

        @XmlAccessorType(XmlAccessType.FIELD)
        @XmlType(name = "\u0441\u0442\u0430\u0442\u0443\u0441\u0410\u043a\u043a\u0440\u0435\u0434\u0438\u0442\u0430" +
                "\u0446\u0438\u0438")

        public static class AccredHistory {

            @XmlElement(name = "\u0421\u0442\u0430\u0442\u0443\u0441\u0410\u043a\u043a\u0440\u0435\u0434\u0438\u0442" +
                    "\u0430\u0446\u0438\u0438",
                    required = true)

            protected List<AccrStatus> accrStatuses;


            public List<AccrStatus> getAccrStatuses() {
                if (accrStatuses == null) {
                    accrStatuses = new ArrayList<AccrStatus>();
                }
                return this.accrStatuses;
            }

        }

        @XmlAccessorType(XmlAccessType.FIELD)
        @XmlType(name = "\u043f\u0440\u043e\u0433\u0440\u0430\u043c\u043c\u043d\u043e\u0410\u043f\u043f\u0430\u0440" +
                "\u0430\u0442\u043d\u044b\u0439\u041a\u043e\u043c\u043f\u043b\u0435\u043a\u0441")

        public static class PAKs {

            @XmlElement(name = "\u041f\u0440\u043e\u0433\u0440\u0430\u043c\u043c\u043d\u043e\u0410\u043f\u043f\u0430" +
                    "\u0440\u0430\u0442\u043d\u044b\u0439\u041a\u043e\u043c\u043f\u043b\u0435\u043a\u0441")

            protected List<PAK> PAK;


            public List<PAK> getPAK() {
                if (PAK == null) {
                    PAK = new ArrayList<PAK>();
                }
                return this.PAK;
            }

            @XmlAccessorType(XmlAccessType.FIELD)
            @XmlType(name = "\u043a\u043b\u044e\u0447\u0438\u0423\u043f\u043e\u043b\u043d\u043e\u043c\u043e\u0447" +
                    "\u0435\u043d\u043d\u044b\u0445\u041b\u0438\u0446")

            public static class PAK {

                @XmlElement(name = "\u041f\u0441\u0435\u0432\u0434\u043e\u043d\u0438\u043c", required = true)

                protected String nickName;
                @XmlElement(name = "\u041a\u043b\u0430\u0441\u0441\u0421\u0440\u0435\u0434\u0441\u0442\u0432\u042d" +
                        "\u041f",
                        required = true)

                protected String cryptyTypeClass;
                @XmlElement(name = "\u0410\u0434\u0440\u0435\u0441", required = true)

                protected Address address;
                @XmlElement(name = "\u0421\u0440\u0435\u0434\u0441\u0442\u0432\u0430\u0423\u0426", required = true)

                protected String CaSoft;
                @XmlElement(name = "\u041a\u043b\u044e\u0447\u0438\u0423\u043f\u043e\u043b\u043d\u043e\u043c\u043e" +
                        "\u0447\u0435\u043d\u043d\u044b\u0445\u041b\u0438\u0446",
                        required = true)

                protected Keys keys;

                public String getNickName() {
                    return nickName;
                }

                public void setNickName(String value) {
                    this.nickName = value;
                }

                public String getCryptyTypeClass() {
                    return cryptyTypeClass;
                }

                public void setCryptyTypeClass(String value) {
                    this.cryptyTypeClass = value;
                }

                public Address getAddress() {
                    return address;
                }

                public void setAddress(Address value) {
                    this.address = value;
                }

                public String getCaSoft() {
                    return CaSoft;
                }

                public void setCaSoft(String value) {
                    this.CaSoft = value;
                }

                public Keys getKeys() {
                    return keys;
                }

                public void setKeys(Keys value) {
                    this.keys = value;
                }

                @XmlAccessorType(XmlAccessType.FIELD)
                @XmlType(name = "Ключи")

                public static class Keys {

                    @XmlElement(name = "\u041a\u043b\u044e\u0447", required = true)

                    protected List<Key> key;

                    public List<Key> getKey() {
                        if (key == null) {
                            key = new ArrayList<Key>();
                        }
                        return this.key;
                    }

                    @XmlAccessorType(XmlAccessType.FIELD)
                    @XmlType(name = "Ключ")

                    public static class Key {

                        @XmlElement(name = "\u0418\u0434\u0435\u043d\u0442\u0438\u0444\u0438\u043a\u0430\u0442\u043e" +
                                "\u0440\u041a\u043b\u044e\u0447\u0430",
                                required = true)

                        protected Object keyId;
                        @XmlElement(name = "\u0410\u0434\u0440\u0435\u0441\u0430\u0421\u043f\u0438\u0441\u043a\u043e" +
                                "\u0432\u041e\u0442\u0437\u044b\u0432\u0430",
                                required = true)

                        protected CrlUrls crlUrls;
                        @XmlElement(name = "\u0421\u0435\u0440\u0442\u0438\u0444\u0438\u043a\u0430\u0442\u044b",
                                required = true)

                        protected Certs certs;

                        public Object getKeyId() {
                            return keyId;
                        }

                        public void setKeyId(Object value) {
                            this.keyId = value;
                        }

                        public CrlUrls getCrlUrls() {
                            return crlUrls;
                        }

                        public void setCrlUrls(CrlUrls value) {
                            this.crlUrls = value;
                        }

                        public Certs getCerts() {
                            return certs;
                        }


                        public void setCerts(Certs value) {
                            this.certs = value;
                        }


                        @XmlAccessorType(XmlAccessType.FIELD)
                        @XmlType(name = "\u0430\u0434\u0440\u0435\u0441")

                        public static class CrlUrls {

                            @XmlElement(name = "\u0410\u0434\u0440\u0435\u0441")

                            protected List<String> address;


                            public List<String> getAddress() {
                                if (address == null) {
                                    address = new ArrayList<String>();
                                }
                                return this.address;
                            }

                        }

                        @XmlAccessorType(XmlAccessType.FIELD)
                        @XmlType(name = "\u0434\u0430\u043d\u043d\u044b\u0435\u0421\u0435\u0440\u0442\u0438\u0444" +
                                "\u0438\u043a\u0430\u0442\u0430")

                        public static class Certs {

                            @XmlElement(name = "\u0414\u0430\u043d\u043d\u044b\u0435\u0421\u0435\u0440\u0442\u0438" +
                                    "\u0444\u0438\u043a\u0430\u0442\u0430")

                            protected List<CertData> certData;

                            public List<CertData> getCertData() {
                                if (certData == null) {
                                    certData = new ArrayList<CertData>();
                                }
                                return this.certData;
                            }
                        }
                    }
                }
            }
        }
    }
}
