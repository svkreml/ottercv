package svkreml.tsl.tsl;


import jakarta.xml.bind.annotation.*;
import lombok.Getter;
import lombok.Setter;

import javax.xml.datatype.XMLGregorianCalendar;
import java.util.ArrayList;
import java.util.List;


@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "АккредитованныеУдостоверяющиеЦентры")
@XmlRootElement(name = "АккредитованныеУдостоверяющиеЦентры")
@Setter
@Getter
public class ACA {

    @XmlElement(name = "Версия")

    protected int version;
    @XmlElement(name = "Дата", required = true)
    @XmlSchemaType(name = "dateTime")

    protected XMLGregorianCalendar date;
    @XmlElement(name = "УдостоверяющийЦ" +
            "ентр")

    protected List<CA> CA;

    public List<CA> getCA() {
        if (CA == null) {
            CA = new ArrayList<CA>();
        }
        return this.CA;
    }

    @XmlAccessorType(XmlAccessType.FIELD)
    @XmlType(name = "CA")

    @Getter
    @Setter
    public static class CA {

       @XmlElement(name = "Название", required = true)

        protected String name;
        @XmlElement(name = "ЭлектроннаяПоч" +
                "та",
                required = true)

        protected String email;
        @XmlElement(name = "КраткоеНазвание",
                required = true)

        protected String shortName;
        @XmlElement(name = "АдресСИнформац" +
                "иейПоУЦ",
                required = true)

        protected String caInfoUrl;
        @XmlElement(name = "АдресСИнформац" +
                "иейПоРеестрамСер" +
                "тификатов")

        protected String anotherUrl;
        @XmlElement(name = "Адрес", required = true)

        protected Address address;
        @XmlElement(name = "ПрограммноАппа" +
                "ратныеКомплексы",
                required = true)
        protected PAKs PAKs;

        @XmlElement(name = "ИНН", required = true)
        protected String inn;

        @XmlElement(name = "ОГРН", required = true)
        protected String ogrn;
        @XmlElement(name = "РеестровыйНомер")

        protected int regNumber;
        @XmlElement(name = "СтатусАккредитации",
                required = true)

        protected AccrStatus accrStatus;
        @XmlElement(name = "ИсторияСтатусо" +
                "вАккредитации",
                required = true)

        protected AccredHistory accredHistory;
        @XmlElement(name = "ПолномочияПере" +
                "даныУЦсОГРН")

        protected Object wtf;

        @XmlAccessorType(XmlAccessType.FIELD)
        @XmlType(name = "статусАккредита" +
                "ции")

        public static class AccredHistory {

            @XmlElement(name = "СтатусАккредит" +
                    "ации",
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
        @XmlType(name = "программноАппаратныйКомплекс")
        public static class PAKs {

            @XmlElement(name = "ПрограммноАппаратныйКомплекс")
            protected List<PAK> PAK;


            public List<PAK> getPAK() {
                if (PAK == null) {
                    PAK = new ArrayList<PAK>();
                }
                return this.PAK;
            }

            @Setter @Getter @XmlAccessorType(XmlAccessType.FIELD)
            @XmlType(name = "ключиУполномоченныхЛиц")
            public static class PAK {

                @XmlElement(name = "Псевдоним", required = true)

                protected String nickName;
                @XmlElement(name = "КлассСредствЭ" +
                        "П",
                        required = true)

                protected String cryptyTypeClass;
                @XmlElement(name = "Адрес", required = true)

                protected Address address;
                @XmlElement(name = "СредстваУЦ", required = true)

                protected String CaSoft;
                @XmlElement(name = "КлючиУполномо" +
                        "ченныхЛиц",
                        required = true)

                protected Keys keys;

                @XmlAccessorType(XmlAccessType.FIELD)
                @XmlType(name = "Ключи")
                public static class Keys {

                    @XmlElement(name = "Ключ", required = true)
                    protected List<Key> key;

                    public List<Key> getKey() {
                        if (key == null) {
                            key = new ArrayList<Key>();
                        }
                        return this.key;
                    }

                    @Setter
                    @Getter
                    @XmlAccessorType(XmlAccessType.FIELD)
                    @XmlType(name = "Ключ")
                    public static class Key {

                        @XmlElement(name = "ИдентификаторКлюча",
                                required = true)
                        protected Object keyId;
                        @XmlElement(name = "АдресаСписковОтзыва",
                                required = true)
                        protected CrlUrls crlUrls;
                        @XmlElement(name = "Сертификаты",
                                required = true)
                        protected Certs certs;


                        @XmlAccessorType(XmlAccessType.FIELD)
                        @XmlType(name = "адрес")
                        public static class CrlUrls {

                            @XmlElement(name = "Адрес")

                            protected List<String> address;


                            public List<String> getAddress() {
                                if (address == null) {
                                    address = new ArrayList<String>();
                                }
                                return this.address;
                            }

                        }

                        @XmlAccessorType(XmlAccessType.FIELD)
                        @XmlType(name = "данныеСертиф" +
                                "иката")
                        public static class Certs {

                            @XmlElement(name = "ДанныеСерти" +
                                    "фиката")

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
