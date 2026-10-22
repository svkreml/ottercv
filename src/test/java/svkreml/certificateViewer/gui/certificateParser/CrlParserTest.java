package svkreml.certificateViewer.gui.certificateParser;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import svkreml.certificateViewer.gui.api.model.CertificateModel;
import svkreml.certificateViewer.gui.api.model.CrlModel;
import svkreml.certificateViewer.gui.localization.ru.Localization;

import java.io.File;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;

class CrlParserTest {

    private static final String ROOT_CRL = "src/test/resources/crl/root.crl";
    private static final String INTERMEDIATE_CRL = "src/test/resources/crl/intermediate.crl";

    @BeforeAll
    static void setup() {
        TestCertUtils.ensureBcProvider();
    }

    @Test
    void parsesRootCrl() throws Exception {
        CrlModel model = parse(ROOT_CRL);
        CrlModel.CrlGeneralInfo info = model.getGeneralInfo();

        assertThat(info.getIssuer()).contains("Восход");
        assertThat(info.getVersion()).isEqualTo("V2");
        assertThat(info.getSignatureAlgorithm()).isNotBlank();
        assertThat(info.getCrlNumber()).isNotBlank();
        assertThat(info.getThisUpdate()).isNotNull();
        assertThat(info.getNextUpdate()).isNotNull();
        assertThat(info.getRevokedCount()).isZero();
        assertThat(model.getRevokedCertificates()).isEmpty();
        assertThat(model.getDetails()).isNotEmpty();
        assertThat(info.getStatusDetails().getValue())
                .contains(Localization.init().CRL_CHECKING_SIGNATURE);
    }

    @Test
    void parsesIntermediateCrl() throws Exception {
        CrlModel model = parse(INTERMEDIATE_CRL);
        CrlModel.CrlGeneralInfo info = model.getGeneralInfo();

        assertThat(info.getIssuer()).contains("Восход");
        assertThat(info.getIssuerFull()).contains("Выдра");
        assertThat(info.getRevokedCount()).isZero();
        assertThat(model.getCrlHolder()).isNotNull();
    }

    @Test
    void crlDetailsContainIssuerAndThumbprints() throws Exception {
        CrlModel model = parse(ROOT_CRL);

        assertThat(model.getDetails())
                .extracting(CertificateModel.CertificateDetail::getField)
                .contains(
                        Localization.init().TAB_DETAIL_TABLE_KEY_CRL_ISSUER,
                        Localization.init().TAB_DETAIL_TABLE_KEY_THUMBPRINT_VALUE);
    }

    @Test
    void parsesRevokedCertificateEntry() throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA", "BC").generateKeyPair();
        Date thisUpdate = new Date();
        X509v2CRLBuilder builder = new X509v2CRLBuilder(new X500Name("CN=Test CA"), thisUpdate);
        builder.setNextUpdate(new Date(thisUpdate.getTime() + 86_400_000L));
        Date revocationDate = new Date(thisUpdate.getTime() - 3_600_000L);
        builder.addCRLEntry(BigInteger.valueOf(1234), revocationDate, CRLReason.keyCompromise);
        X509CRLHolder holder = builder.build(
                new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(keyPair.getPrivate()));

        CrlModel model = CrlParser.getCrlModel(Localization.init(), holder);

        assertThat(model.getGeneralInfo().getVersion()).isEqualTo("V2");
        assertThat(model.getRevokedCertificates()).hasSize(1);
        CrlModel.RevokedCertificate revoked = model.getRevokedCertificates().getFirst();
        assertThat(revoked.getSerialNumber()).isEqualTo("4D2");
        assertThat(revoked.getRevocationDate().toInstant().getEpochSecond())
                .isEqualTo(revocationDate.toInstant().getEpochSecond());
        assertThat(revoked.getReason()).isEqualTo("Компрометация ключа");
        assertThat(revoked.getDetails()).isNotEmpty();
    }

    private static CrlModel parse(String path) throws Exception {
        byte[] bytes = Files.readAllBytes(new File(path).toPath());
        return CrlParser.getCrlModel(Localization.init(), new X509CRLHolder(bytes));
    }
}
