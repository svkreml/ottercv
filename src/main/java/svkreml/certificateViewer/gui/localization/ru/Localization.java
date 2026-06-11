package svkreml.certificateViewer.gui.localization.ru;


import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import svkreml.certificateViewer.gui.api.model.CertificateStatus;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;


public class Localization {

    public static final String DEFAULT_PATH = System.getProperty("user.home") + "/.ottercv";
    public final String TSL_LOCATION = "https://e-trust.gosuslugi.ru/CA/DownloadTSL?schemaVersion=0";
    public String TSL_LOCATION_BKS = DEFAULT_PATH + "/tsl.bks";
    public final String PROGRAM_TITLE = "Certificate";
    public final String TAB_GENERAL_TITLE = "General";
    public final String TAB_CHAIN_TITLE = "Chain";
    public final String BUTTON_OK = "   OK   ";
    public final String CERT_STATUS_TRUSTED = "Сертификат действителен";
    public final String CERT_STATUS_UNTRUSTED_ROOT = "Корневой сертификат данной цепочки не в списке доверенных";
    public final String CERT_STATUS_UNTRUSTED_CHAIN = "Корневой сертификат не в списке доверенных";
    public final String CERT_STATUS_BROKEN = "Подпись сертификата или сам сертификат невалиден";
    public final String CERT_STATUS_OVERDUE = "Срок действия сертификата истёк или не наступил";
    public final String CERT_STATUS_UNKNOWN = "Состояние сертификата не проверялось";
    public final String TAB_GENERAL_LABEL_CERTIFICATE_INFORMATION = "Сведения о сертификате:";
    public final String TAB_GENERAL_VALID_FROM = "Действителен с ";
    public final String TAB_GENERAL_VALID_TO = " по ";
    public final String TAB_GENERAL_ISSUED_BY = "Субъект:";
    public final String TAB_GENERAL_ISSUED_TO = "Издатель:";

    public final String TAB_DETAILS_TITLE = "Подробности";
    public final String TAB_DETAILS_LABEL_CERTIFICATION_PATH = "Цепочка сертификатов:";
    public final String TAB_DETAILS_LABEL_SHOW = "Показать:";
    public final String TAB_DETAIL_TABLE_KEY_VERSION = "Версия";
    public final String TAB_DETAIL_TABLE_KEY_SERIAL_NUMBER = "Серийный номер";
    public final String TAB_DETAIL_TABLE_KEY_ALG = "Алгоритм подписи";
    public final String TAB_DETAIL_TABLE_KEY_ISSUER = "Издатель";
    public final String TAB_DETAIL_TABLE_KEY_VALID_FROM = "Действителен с";
    public final String TAB_DETAIL_TABLE_KEY_VALID_UNTIL = "Действителен по";
    public final String TAB_DETAIL_TABLE_KEY_SUBJECT = "Субъект";
    public final String TAB_DETAIL_TABLE_KEY_PUBLIC_KEY = "Публичный ключ";
    public final String TAB_DETAIL_TABLE_KEY_PUBLIC_KEY_DETAILS = "Параметры ключа ЭП";
    public final String TAB_DETAIL_TABLE_KEY_THUMBPRINT_ALG = "Алгоритм отпечатка";
    public final String TAB_DETAIL_TABLE_KEY_THUMBPRINT_VALUE = "Отпечаток";
    public final String TAB_DETAIL_TABLE_KEY_PUBLIC_KEY_PARAMS = "Параметры:";
    public final String TAB_DETAIL_TABLE_KEY_PUBLIC_KEY_RSA_EXP = "Экспонента:";
    public final String TAB_DETAIL_TABLE_KEY_PUBLIC_KEY_LENGTH = "Длина ключа:";
    public final Map<ASN1ObjectIdentifier, String> oidMap = new HashMap<>();

    public final String DATE_FORMAT = "dd.MM.yyyy HH:mm:ss";
    public final String TAB_DETAIL_TABLE_KEY_PUBLIC_KEY_ALG = "Алгоритм:";
    public final String EXTENSIONS_PATH_LEN_CONSTRAINT = "PathLenConstraint:";
    public final String EXTENSIONS_IS_CA = "isCa:";
    public final String EXTENSIONS_PRIVATE_KEY_VALID_FROM = "С:";
    public final String EXTENSIONS_PRIVATE_KEY_VALID_TO = "По:";
    public final String BUTTON_TO_BASE64 = "->Base64";
    public final String LOADING = "Загрузка, подождите...";

    private static final DateTimeFormatter DATE_FORMATTER =
            DateTimeFormatter.ofPattern("dd.MM.yyyy HH:mm:ss");

    public static Localization init() {
        Localization localization = new Localization();
        {

            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.840.10040.4.3"), "dsa-with-sha1");

            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.840.10045.4.1"), "ecdsa-with-SHA1");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.840.10045.4.3.1"), "ecdsa-with-SHA224");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.840.10045.4.3.2"), "ecdsa-with-SHA256");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.840.10045.4.3.3"), "ecdsa-with-SHA384");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.840.10045.4.3.4"), "ecdsa-with-SHA512");

            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.840.113549.1.1.1"), "RSAEncryption");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.840.113549.1.1.2"), "md2WithRSAEncryption");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.840.113549.1.1.4"), "md5WithRSAEncryption");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.840.113549.1.1.5"), "sha1WithRSAEncryption");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.840.113549.1.1.10"), "id-RSASSA-PSS");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.840.113549.1.1.11"), "sha256WthRSAEncryption");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.840.113549.1.1.12"), "sha384WithRSAEncryption");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.840.113549.1.1.13"), "sha512WithRSAEncryption");

            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.21"),
                    "Алгоритм шифрования ГОСТ 28147-89, szOID_CP_GOST_28147");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.7.1.1.5.1"),
                    "Алгоритм шифрования ГОСТ Р 34.12-2015 Магма, szOID_CP_GOST_R3412_2015_M");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.7.1.1.5.2"),
                    "Алгоритм шифрования ГОСТ Р 34.12-2015 Кузнечик, szOID_CP_GOST_R3412_2015_K");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.9"),
                    "Функция хэширования ГОСТ Р 34.11-94, szOID_CP_GOST_R3411");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.7.1.1.2.2"),
                    "Функция хэширования ГОСТ Р 34.11-2012, длина выхода 256 бит, szOID_CP_GOST_R3411_12_256");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.7.1.1.2.3"),
                    "Функция хэширования ГОСТ Р 34.11-2012, длина выхода 512 бит, szOID_CP_GOST_R3411_12_512");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.20"),
                    "Алгоритм ГОСТ Р 34.10-94, используемый при экспорте/импорте ключей, szOID_CP_GOST_R3410");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.19"),
                    "Алгоритм ГОСТ Р 34.10-2001, используемый при экспорте/импорте ключей, szOID_CP_GOST_R3410EL");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.7.1.1.1.1"),
                    "Алгоритм ГОСТ Р 34.10-2012 для ключей длины 256 бит, используемый при экспорте/импорте ключей, " +
                            "szOID_CP_GOST_R3410_12_256");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.7.1.1.1.2"),
                    "Алгоритм ГОСТ Р 34.10-2012 для ключей длины 512 бит, используемый при экспорте/импорте ключей, " +
                            "szOID_CP_GOST_R3410_12_512");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.99"),
                    "Алгоритм Диффи-Хеллмана на базе потенциальной функции, szOID_CP_DH_EX");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.98"),
                    "Алгоритм Диффи-Хеллмана на базе эллиптической кривой, szOID_CP_DH_EL");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.7.1.1.6.1"),
                    "Алгоритм Диффи-Хеллмана на базе эллиптической кривой для ключей длины 256 бит, " +
                            "szOID_CP_DH_12_256");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.7.1.1.6.2"),
                    "Алгоритм Диффи-Хеллмана на базе эллиптической кривой для ключей длины 512 бит, " +
                            "szOID_CP_DH_12_512");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.4"),
                    "Алгоритм цифровой подписи ГОСТ Р 34.10-94, szOID_CP_GOST_R3411_R3410");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.3"),
                    "Алгоритм цифровой подписи ГОСТ Р 34.10-2001, szOID_CP_GOST_R3411_R3410EL");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.7.1.1.3.2"),
                    "Алгоритм цифровой подписи ГОСТ Р 34.10-2012 для ключей длины 256 бит, " +
                            "szOID_CP_GOST_R3411_12_256_R3410");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.7.1.1.3.3"),
                    "Алгоритм цифровой подписи ГОСТ Р 34.10-2012 для ключей длины 512 бит, " +
                            "szOID_CP_GOST_R3411_12_512_R3410");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.34.1"),
                    "Аудит TLS-трафика, szOID_KP_TLS_PROXY");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.34.2"),
                    "Идентификация пользователя на центре регистрации, szOID_KP_RA_CLIENT_AUTH");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.34.3"),
                    "Подпись содержимого сервера Интернет, szOID_KP_WEB_CONTENT_SIGNING");


            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.30.0"),
                    "Тестовый узел замены, szOID_GostR3411_94_TestParamSet");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.30.1"),
                    "Узел замены функции хэширования по умолчанию, вариант \"Верба - О\", " +
                            "szOID_GostR3411_94_CryptoProParamSet");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.30.2"),
                    "Узел замены функции хэширования, вариант 1, szOID_GostR3411_94_CryptoPro_B_ParamSet");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.30.3"),
                    "Узел замены функции хэширования, вариант 2, szOID_GostR3411_94_CryptoPro_C_ParamSet");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.30.4"),
                    "Узел замены функции хэширования, вариант 3, szOID_GostR3411_94_CryptoPro_D_ParamSet");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.31.0"),
                    "Тестовый узел замены алгоритма шифрования, szOID_Gost28147_89_TestParamSet");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.31.1"),
                    "Узел замены алгоритма шифрования по умолчанию, вариант \"Верба - О\", " +
                            "szOID_Gost28147_89_CryptoPro_A_ParamSet");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.31.2"),
                    "Узел замены алгоритма шифрования, вариант 1, szOID_Gost28147_89_CryptoPro_B_ParamSet");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.31.3"),
                    "Узел замены алгоритма шифрования, вариант 2, szOID_Gost28147_89_CryptoPro_C_ParamSet");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.31.4"),
                    "Узел замены алгоритма шифрования, вариант 3, szOID_Gost28147_89_CryptoPro_D_ParamSet");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.31.5"),
                    "Узел замены, вариант карты КриптоРИК, szOID_Gost28147_89_CryptoPro_Oscar_1_1_ParamSet");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.31.6"),
                    "Узел замены, используемый при шифровании с хэшированием, " +
                            "szOID_Gost28147_89_CryptoPro_Oscar_1_0_ParamSet");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.31.12"),
                    "Узел замены алгоритма шифрования, вариант ТК26 2, szOID_Gost28147_89_TC26_A_ParamSet");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.31.13"),
                    "Узел замены алгоритма шифрования, вариант ТК26 1, szOID_Gost28147_89_TC26_B_ParamSet");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.31.14"),
                    "Узел замены алгоритма шифрования, вариант ТК26 3, szOID_Gost28147_89_TC26_C_ParamSet");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.31.15"),
                    "Узел замены алгоритма шифрования, вариант ТК26 4, szOID_Gost28147_89_TC26_D_ParamSet");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.31.16"),
                    "Узел замены алгоритма шифрования, вариант ТК26 5, szOID_Gost28147_89_TC26_E_ParamSet");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.31.17"),
                    "Узел замены алгоритма шифрования, вариант ТК26 6, szOID_Gost28147_89_TC26_F_ParamSet");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.7.1.2.5.1.1"),
                    "Узел замены алгоритма шифрования, вариант ТК26 Z, szOID_Gost28147_89_TC26_Z_ParamSet");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.32.2"),
                    "Параметры P, Q, A цифровой подписи ГОСТ Р 34.10-94, вариант \"Верба - О\". Могут использоваться " +
                            "также в алгоритме Диффи-Хеллмана, szOID_GostR3410_94_CryptoPro_A_ParamSet");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.32.3"),
                    "Параметры P, Q, A цифровой подписи ГОСТ Р 34.10-94, вариант 1. Могут использоваться также в " +
                            "алгоритме Диффи-Хеллмана, szOID_GostR3410_94_CryptoPro_B_ParamSet");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.32.4"),
                    "Параметры P, Q, A цифровой подписи ГОСТ Р 34.10-94, вариант 2. Могут использоваться также в " +
                            "алгоритме Диффи-Хеллмана, szOID_GostR3410_94_CryptoPro_C_ParamSet");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.32.5"),
                    "Параметры P, Q, A цифровой подписи ГОСТ Р 34.10-94, вариант 3. Могут использоваться также в " +
                            "алгоритме Диффи-Хеллмана, szOID_GostR3410_94_CryptoPro_D_ParamSet");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.33.1"),
                    "Параметры P, Q, A алгоритма Диффи-Хеллмана на базе экспоненциальной функции, вариант 1, " +
                            "szOID_GostR3410_94_CryptoPro_XchA_ParamSet");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.33.2"),
                    "Параметры P, Q, A алгоритма Диффи-Хеллмана на базе экспоненциальной функции, вариант 2, " +
                            "szOID_GostR3410_94_CryptoPro_XchB_ParamSet");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.33.3"),
                    "Параметры P, Q, A алгоритма Диффи-Хеллмана на базе экспоненциальной функции, вариант 3, " +
                            "szOID_GostR3410_94_CryptoPro_XchC_ParamSet");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.35.0"),
                    "Тестовые параметры a, b, p, q, (x,y) алгоритма ГОСТ Р 34.10-2001, " +
                            "szOID_GostR3410_2001_TestParamSet");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.35.1"),
                    "Параметры a, b, p, q, (x,y) цифровой подписи и алгоритма Диффи-Хеллмана на базе алгоритма ГОСТ Р" +
                            " 34.10-2001, вариант криптопровайдера, szOID_GostR3410_2001_CryptoPro_A_ParamSet");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.35.2"),
                    "Параметры a, b, p, q, (x,y) цифровой подписи и алгоритма Диффи-Хеллмана на базе алгоритма ГОСТ Р" +
                            " 34.10-2001, вариант карты КриптоРИК, szOID_GostR3410_2001_CryptoPro_B_ParamSet");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.35.3"),
                    "Параметры a, b, p, q, (x,y) цифровой подписи и алгоритма Диффи-Хеллмана на базе алгоритма ГОСТ Р" +
                            " 34.10-2001, вариант 1, szOID_GostR3410_2001_CryptoPro_C_ParamSet");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.36.0"),
                    "Параметры a, b, p, q, (x,y) алгоритма Диффи-Хеллмана на базе алгоритма ГОСТ Р 34.10-2001, " +
                            "вариант криптопровайдера. Используются те же параметры, что и с идентификатором " +
                            "szOID_GostR3410_2001_CryptoPro_A_ParamSet, szOID_GostR3410_2001_CryptoPro_XchA_ParamSet");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.36.1"),
                    "Параметры a, b, p, q, (x,y) цифровой подписи и алгоритма Диффи-Хеллмана на базе алгоритма ГОСТ Р" +
                            " 34.10-2001, вариант 1, szOID_GostR3410_2001_CryptoPro_XchB_ParamSet");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.7.1.2.1.1.1"),
                    "Параметры a, b, p, q, (x,y) цифровой подписи и алгоритма Диффи-Хеллмана на базе алгоритма ГОСТ Р" +
                            " 34.10-2012 256 бит, набор A, szOID_tc26_gost_3410_12_256_paramSetA");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.7.1.2.1.1.2"),
                    "Параметры a, b, p, q, (x,y) цифровой подписи и алгоритма Диффи-Хеллмана на базе алгоритма ГОСТ Р" +
                            " 34.10-2012 256 бит, набор B, szOID_tc26_gost_3410_12_256_paramSetB");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.7.1.2.1.1.3"),
                    "Параметры a, b, p, q, (x,y) цифровой подписи и алгоритма Диффи-Хеллмана на базе алгоритма ГОСТ Р" +
                            " 34.10-2012 256 бит, набор C, szOID_tc26_gost_3410_12_256_paramSetC");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.7.1.2.1.1.4"),
                    "Параметры a, b, p, q, (x,y) цифровой подписи и алгоритма Диффи-Хеллмана на базе алгоритма ГОСТ Р" +
                            " 34.10-2012 256 бит, набор D, szOID_tc26_gost_3410_12_256_paramSetD");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.7.1.2.1.2.1"),
                    "Параметры a, b, p, q, (x,y) цифровой подписи и алгоритма Диффи-Хеллмана на базе алгоритма ГОСТ Р" +
                            " 34.10-2012 512 бит по умолчанию, szOID_tc26_gost_3410_12_512_paramSetA");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.7.1.2.1.2.2"),
                    "Параметры a, b, p, q, (x,y) цифровой подписи и алгоритма Диффи-Хеллмана на базе алгоритма ГОСТ Р" +
                            " 34.10-2012 512 бит, набор B, szOID_tc26_gost_3410_12_512_paramSetB");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.7.1.2.1.2.3"),
                    "Параметры a, b, p, q, (x,y) цифровой подписи и алгоритма Диффи-Хеллмана на базе алгоритма ГОСТ Р" +
                            " 34.10-2012 512 бит, набор C, szOID_tc26_gost_3410_12_512_paramSetC");


            localization.oidMap.put(new ASN1ObjectIdentifier("2.5.29.35"), "Authority key identifier");
            localization.oidMap.put(new ASN1ObjectIdentifier("2.5.29.1"),
                    "Obsolete (formerly, \"authorityKeyIdentifier\")");
            localization.oidMap.put(new ASN1ObjectIdentifier("2.5.29.2"), "Obsolete");
            localization.oidMap.put(new ASN1ObjectIdentifier("2.5.29.4"), "Obsolete");
            localization.oidMap.put(new ASN1ObjectIdentifier("2.5.29.17"), "Subject alternative name");
            localization.oidMap.put(new ASN1ObjectIdentifier("2.5.29.7"), "Obsolete (formerly \"subjectAltName\")");
            localization.oidMap.put(new ASN1ObjectIdentifier("2.5.29.18"), "Issuer alternative name");
            localization.oidMap.put(new ASN1ObjectIdentifier("2.5.29.8"), "Obsolete (formerly, \"issuerAltName\")");
            localization.oidMap.put(new ASN1ObjectIdentifier("2.5.29.19"), "Basic constraints");
            localization.oidMap.put(new ASN1ObjectIdentifier("2.5.29.10"), "Obsolete (formerly, \"basicConstraints\")");
            localization.oidMap.put(new ASN1ObjectIdentifier("2.5.29.15"), "Key usage");
            localization.oidMap.put(new ASN1ObjectIdentifier("2.5.29.32"), "Certificate policies");
            localization.oidMap.put(new ASN1ObjectIdentifier("2.5.29.14"), "Subject key identifier");
            localization.oidMap.put(new ASN1ObjectIdentifier("2.5.29.21"), "Reason code");
            localization.oidMap.put(new ASN1ObjectIdentifier("2.5.29.31"),
                    "Certificate Revocation List (CRL) distribution points");
            localization.oidMap.put(new ASN1ObjectIdentifier("2.5.29.37"), "Extended key usage");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.1"),
                    "Certificate authority information access");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.11"), "\"id-pe-subjectInfoAccess\"");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.2.1.14"), "SPC_CERT_EXTENSIONS_OBJID");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.840.113549.1.9.14"),
                    "PKCS#9 experimental extension request");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.10.2"),
                    "Next Update Location extension or attribute. Value is an encoded GeneralNames");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.10.4.1"),
                    "Microsoft Attribute Object Identifiers -- szOID_YESNO_TRUST_ATTR");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.840.113549.1.9.3"), "\"id-contentType\"");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.840.113549.1.9.4"), "\"id-messageDigest\"");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.840.113549.1.9.5"), "\"id-signingTime\"");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.840.113549.1.9.6"), "\"id-countersignature\"");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.840.113549.1.9.7"),
                    "Challenge Password attribute for use in signatures");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.840.113549.1.9.9"),
                    "PKCS#9 extendedCertificateAttributes");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.840.113549.1.9.15"),
                    "\"aa-smimeCapabilities\" attribute");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.840.113549.1.9.15.1"),
                    "Rivest, Shamir and Adleman (RSA) applied to the S/MIME preferSignedData</code> capability " +
                            "preference");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.2.1"),
                    "Public-Key Infrastructure using X.509 (PKIX) Certificate Practice Statement (CPS) pointer " +
                            "qualifier");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.2.2"),
                    "Public-Key Infrastructure using X.509 (PKIX) policy qualifier \"unotice\"");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1"),
                    "Online Certificate Status Protocol (OCSP)");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.2"), "Certificate authority issuers");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.5"),
                    "Certificate Authority (CA) repository");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.20.2"), "Certificate type extension");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.20.3"), "\"szOID_CERT_MANIFOLD\"");
            localization.oidMap.put(new ASN1ObjectIdentifier("2.16.840.1.113730.1.1"),
                    " certificate type (a Rec. ITU-T X.509 v3 certificate extension used to identify whether the " +
                            "certificate subject is a Secure Sockets Layer (SSL) client, an SSL server or a " +
                            "Certificate Authority (CA))");
            localization.oidMap.put(new ASN1ObjectIdentifier("2.16.840.1.113730.1.2"),
                    "Base Uniform Resource Locator (URL)");
            localization.oidMap.put(new ASN1ObjectIdentifier("2.16.840.1.113730.1.3"),
                    "Revocation Uniform Resource Locator (URL)");
            localization.oidMap.put(new ASN1ObjectIdentifier("2.16.840.1.113730.1.4"),
                    "Certificate Authority (CA) revocation Uniform Resource Locator (URL)");
            localization.oidMap.put(new ASN1ObjectIdentifier("2.16.840.1.113730.1.7"),
                    "Renewal Uniform Resource Locator (URL)");
            localization.oidMap.put(new ASN1ObjectIdentifier("2.16.840.1.113730.1.8"),
                    " Certificate Authority (CA) policy Uniform Resource Locator (URL) (an X.509 v3 certificate " +
                            "extension used to include the URL of a document describing the issuing CA's security " +
                            "policy)");
            localization.oidMap.put(new ASN1ObjectIdentifier("2.16.840.1.113730.1.12"),
                    "Secure Sockets Layer (SSL) server name");
            localization.oidMap.put(new ASN1ObjectIdentifier("2.16.840.1.113730.1.13"),
                    " certificate comment (an X.509 v3 certificate extension used to include free-form text comments " +
                            "inside certificates)");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.2.1.10"), "SPC_SP_AGENCY_INFO_OBJID");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.2.1.27"), "SPC_FINANCIAL_CRITERIA_OBJID");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.2.1.26"), "SPC_MINIMAL_CRITERIA_OBJID");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.21.1"),
                    "Certificate services Certification Authority (CA) version");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.21.22"), "szOID_CERTSRV_CROSSCA_VERSION");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.10.3.3.1"), "szOID_SERIALIZED");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.20.2.3"), "User Principal Name (UPN)");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.31.1"), "szOID_PRODUCT_UPDATE");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.13.2.1"),
                    "\"szOID_ENROLLMENT_NAME_VALUE_PAIR\"");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.13.2.3"), "\"szOID_OS_VERSION\"");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.13.2.2"),
                    "\"szOID_ENROLLMENT_CSP_PROVIDER\"");
            localization.oidMap.put(new ASN1ObjectIdentifier("2.5.29.20"), "Certificate Revocation List (CRL) number");
            localization.oidMap.put(new ASN1ObjectIdentifier("2.5.29.27"),
                    "Certificate Revocation List (CRL) indicator");
            localization.oidMap.put(new ASN1ObjectIdentifier("2.5.29.28"), "Issuing distribution point");
            localization.oidMap.put(new ASN1ObjectIdentifier("2.5.29.46"), "\"id-ce-freshestCRL\"");
            localization.oidMap.put(new ASN1ObjectIdentifier("2.5.29.30"), "Name constraints");
            localization.oidMap.put(new ASN1ObjectIdentifier("2.5.29.33"), "Policy mappings");
            localization.oidMap.put(new ASN1ObjectIdentifier("2.5.29.5"), "Obsolete");
            localization.oidMap.put(new ASN1ObjectIdentifier("2.5.29.36"), "Policy constraints");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.10.9.1"),
                    "Microsoft certificate extension containing cross certificate distribution points -- " +
                            "szOID_CROSS_CERT_DIST_POINTS");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.21.10"),
                    "Microsoft, Расширенное использование ключа, szOID_APPLICATION_CERT_POLICIES");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.21.11"),
                    "szOID_APPLICATION_POLICY_MAPPINGS");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.21.12"),
                    "szOID_APPLICATION_POLICY_CONSTRAINTS");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.12.2"), "\"id-cct-PKIData\"");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.12.3"), "\"id-cct-PKIResponse\"");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.7"),
                    "Certificate Management over Cryptographic message syntax (CMC) controls");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.7.1"),
                    "id-cmc-cMCStatusInfo</code> control");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.7.8"), "\"id-cmc-addExtensions\"");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.10.10.1"), "szOID_CMC_ADD_ATTRIBUTES");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.840.113549.1.7.1"), "\"id-data\"");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.840.113549.1.7.2"),
                    "Rivest, Shamir and Adleman (RSA) applied over the PKCS#7 ASN.1 SignedData type");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.840.113549.1.7.3"),
                    "Rivest, Shamir and Adleman (RSA) applied over the PKCS#7 ASN.1 EnvelopedData type");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.840.113549.1.7.4"),
                    "Rivest, Shamir and Adleman (RSA) applied over the PKCS#7 ASN.1 SignedAndEnvelopedData type");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.840.113549.1.7.5"),
                    "Rivest, Shamir and Adleman (RSA) applied over the PKCS#7 ASN.1 DigestedData type");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.840.113549.1.7.6"),
                    "Rivest, Shamir and Adleman (RSA) applied over the PKCS#7 ASN.1 EncryptedData type");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.21.2"),
                    "szOID_CERTSRV_PREVIOUS_CERT_HASH");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.21.3"), "szOID_CRL_VIRTUAL_BASE");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.21.4"), "szOID_CRL_NEXT_PUBLISH");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.21.5"), "szOID_KP_CA_EXCHANGE");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.21.6"), "szOID_KP_KEY_RECOVERY_AGENT");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.21.7"), "szOID_CERTIFICATE_TEMPLATE");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.21.8"), "szOID_ENTERPRISE_OID_ROOT");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.21.9"), "szOID_RDN_DUMMY_SIGNER");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.21.13"),
                    "Attribute added to an certificate request when key archival is desired (szOID_ARCHIVED_KEY_ATTR)");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.21.14"), "szOID_CRL_SELF_CDP");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.21.15"),
                    "szOID_REQUIRE_CERT_CHAIN_POLICY");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.7.5"), "\"id-cmc-transactionId\"");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.7.6"), "\"id-cmc-senderNonce\"");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.7.7"), "\"id-cmc-recipientNonce\"");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.7.18"), "\"id-cmc-regInfo\"");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.7.15"), "\"id-cmc-getCert\"");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.7.16"), "\"id-cmc-getCRL\"");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.7.17"), "\"id-cmc-revokeRequest\"");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.7.21"), "\"id-cmc-queryPending\"");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.10.1"),
                    "PKCS #7 ContentType Object Identifier for Certificate Trust List (CTL) szOID_CTL");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.21.16"), "szOID_ARCHIVED_KEY_CERT_HASH");
            localization.oidMap.put(new ASN1ObjectIdentifier("2.5.29.16"), "Private key usage period");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.21.20"), "szOID_REQUEST_CLIENT_INFO");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.12"), "\"id-pe-logotype\"");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.2"), "\"biometricInfo\" extension");
            localization.oidMap.put(new ASN1ObjectIdentifier("2.5.29.54"),
                    "Rec. ITU-T X.509 version 3 certificate extension InhibitAnyPolicy");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1.5"), "No check extension");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.3"), "\"qcStatements\" extension");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.25.1"), "\"szOID_NTDS_REPLICATION\"");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.7.24"), "\"id-cmc-confirmCertAcceptance\"");
            localization.oidMap.put(new ASN1ObjectIdentifier("2.16.840.1.113733.1.6.11"),
                    "\"verisignOnsiteJurisdictionHash\"");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.60.1.1"),
                    "Root program qualifier flags, used in pbData field of CERT_POLICY_QUALIFIER_INFO structure");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.11"), "\"id-pe-subjectInfoAccess\"");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1.1"),
                    "Online Certificate Status Protocol (OCSP) basic response");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1.2"),
                    "Online Certificate Status Protocol (OCSP) nonce extension");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1.3"), "\"re-ocsp-crl\" extension");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1.4"), "\"re-ocsp-response\" extension");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1.5"), "No check extension");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1.6"), "Archive cutoff extension");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1.7"), "OCSP Service Locator Extension");


            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2"),
                    "Extended validation certificates");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.1"), "Certificate authority issuers");

            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.10.12.1"),
                    "szOID_ANY_APPLICATION_POLICY");

            localization.oidMap.put(new ASN1ObjectIdentifier("2.5.29.32.0"), "Все политики выдачи");

            localization.oidMap.put(new ASN1ObjectIdentifier("2.23.140.1.2"),
                    "Сертификат, выданный в соответствии с базовыми требованиями");
            localization.oidMap.put(new ASN1ObjectIdentifier("2.23.140.1.2.1"),
                    "Соответствует базовым требованиям - не указана идентификация лица");
            localization.oidMap.put(new ASN1ObjectIdentifier("2.23.140.1.2.2"),
                    "Соответствует базовым требованиям - заявлена ​​идентификация организации");
            localization.oidMap.put(new ASN1ObjectIdentifier("2.23.140.1.2.3"),
                    "Соответствует базовым требованиям - заявлена индивидуальная идентификация");
            localization.oidMap.put(new ASN1ObjectIdentifier("2.23.140.1.3"),
                    "Соответствует базовым требованиям - для расширенной EV проверки");
            localization.oidMap.put(new ASN1ObjectIdentifier("2.23.140.1.3.1"),
                    "Соответствует базовым требованиям - для .onion EV сертификатов");

            localization.oidMap.put(new ASN1ObjectIdentifier("2.16.840.1.114412.1.2"),
                    "Digicert Domain‐validated (DV) Secure Sockets Layer (SSL) certificate");
            localization.oidMap.put(new ASN1ObjectIdentifier("2.16.840.1.114412.1.1"),
                    "Digicert Organizationally‐Validated (OV) Secure Sockets Layer (SSL) Certificate");
            localization.oidMap.put(new ASN1ObjectIdentifier("2.16.840.1.114412.2.1"),
                    "DigiCert Extended Validation (EV) Certification Practice Statement (CPS) v. 1.0.3");
            localization.oidMap.put(new ASN1ObjectIdentifier("2.16.840.1.113733.1.7.54"),
                    "Symantec Reserved certificate policy (Symantec/id-CABF-OVandDVvalidation)");

            /*
            *
1.3.6.1.5.5.7.3.1	serverAuth	Сертификат X 509 может использоваться как сертификат серверной аутентификации
1.3.6.1.5.5.7.3.2	clientAuth	Сертификат X 509 может использоваться как сертификат клиентской аутентификации
1.3.6.1.5.5.7.3.3	codeSigning	Сертификат X 509 может использоваться для электронной подписи кода
1.3.6.1.5.5.7.3.4	emailProtection	Сертификат X 509 может использоваться для защиты электронной почты (электронная
* подпись, шифрование, key agreement)
1.3.6.1.5.5.7.3.8	timeStamping	Сертификат X 509 может использоваться для включения значения хэш-функции при
* создании штампа времени на документы в Службе штампов времени
1.3.6.1.5.5.7.3.9	OCSPSigning	Сертификат X 509 может использоваться для формирования электронной подписи
* OCSP-запросов
            * */
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.3.1"), "serverAuth");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.3.2"), "clientAuth");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.3.3"), "codeSigning");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.3.4"), "emailProtection");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.3.8"), "timeStamping");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.3.9"), "OCSPSigning");


            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.100.1"), "OGRN");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.3.131.1.1"), "INN");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.100.3"), "SNILS");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.100.5"), "ORGNIP");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.3.141.1.1"), "РНС ФСС");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.3.141.1.2"), "КП ФСС");
            localization.oidMap.put(new ASN1ObjectIdentifier("2.5.4.65"), "Псевдоним");
            localization.oidMap.put(new ASN1ObjectIdentifier("2.5.4.16"), "Почтовый адрес");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.100.111"),
                    "Средство электронной подписи владельца");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.100.112"),
                    "Средства электронной подписи и УЦ издателя");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.100.113.1"), "Класс средства ЭП КС1");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.100.113.2"), "Класс средства ЭП КС2");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.100.113.3"), "Класс средства ЭП КС3");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.100.113.4"), "Класс средства ЭП КВ1");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.100.113.5"), "Класс средства ЭП КВ2");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.100.113.5"), "Класс средства ЭП КВ2");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.100.113.6"), "Класс средства ЭП КА1");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.100.114"), "identificationKind");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.100.114.1"), "Класс средств УЦ КС1");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.100.114.2"), "Класс средств УЦ КС2");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.100.114.3"), "Класс средств УЦ КС3");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.100.114.4"), "Класс средств УЦ КВ1");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.100.114.5"), "Класс средств УЦ КВ2");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.100.114.6"), "Класс средств УЦ КА1");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.19"), "ГОСТ Р 34.10-2001");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.21"), "ГОСТ 28147-89");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.3"), "ГОСТ Р 34.11/34.10-2001");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.30.1"), "ГОСТ Р 34.11-94");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.30.2"), "ГОСТ Р 34.11-94");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.30.3"), "ГОСТ Р 34.11-94");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.30.4"), "ГОСТ Р 34.11-94");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.31.1"), "ГОСТ 28147-89");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.31.12"), "ГОСТ 28147-89");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.31.13"), "ГОСТ 28147-89");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.31.14"), "ГОСТ 28147-89");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.31.15"), "ГОСТ 28147-89");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.31.16"), "ГОСТ 28147-89");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.31.17"), "ГОСТ 28147-89");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.31.2"), "ГОСТ 28147-89");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.31.3"), "ГОСТ 28147-89");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.31.4"), "ГОСТ 28147-89");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.31.5"), "ГОСТ 28147-89");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.31.6"), "ГОСТ 28147-89");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.31.7"), "ГОСТ 28147-89");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.34.1"), "Аудит TLS трафика");
            localization.oidMap.put(new ASN1ObjectIdentifier("1.2.643.2.2.34.10"), "КриптоПро ЦР");

        }
        return localization;
    }


    public String convertOidToString(ASN1ObjectIdentifier asn1) {
        return oidMap.getOrDefault(asn1, asn1.getId());
    }

    public String convertOidToString(ASN1ObjectIdentifier asn1, String defaultValue) {
        return oidMap.getOrDefault(asn1, defaultValue);
    }

    public String nameCertificateStatus(CertificateStatus certificateStatus) {
        return switch (certificateStatus) {
            case TRUSTED -> CERT_STATUS_TRUSTED;
            case UNTRUSTED_ROOT -> CERT_STATUS_UNTRUSTED_ROOT;
            case UNTRUSTED_CHAIN -> CERT_STATUS_UNTRUSTED_CHAIN;
            case BROKEN -> CERT_STATUS_BROKEN;
            case OVERDUE -> CERT_STATUS_OVERDUE;
            case UNKNOWN -> CERT_STATUS_UNKNOWN;
        };
    }

    public String formatDate(Date date) {
        return DATE_FORMATTER.format(date.toInstant().atZone(ZoneId.systemDefault()));
    }

}
