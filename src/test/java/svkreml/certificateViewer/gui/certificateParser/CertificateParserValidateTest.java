package svkreml.certificateViewer.gui.certificateParser;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import svkreml.certificateViewer.gui.api.model.CertificateModel;
import svkreml.certificateViewer.gui.api.model.CertificateStatus;
import svkreml.certificateViewer.gui.localization.ru.Localization;

import java.security.Security;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;

class CertificateParserValidateTest {

    @BeforeAll
    static void setup() {
        TestCertUtils.ensureBcProvider();
    }

    @Test
    void validateSelfSignedCertFromResources() throws Exception {
        X509CertificateHolder holder = TestCertUtils.loadHolderFromResources("2F0CB09BE3550EF17EC4F29C90ABD18BFCAAD63A.cer");

        Localization localization = new Localization();
        localization.TSL_LOCATION_BKS = TestCertUtils.createTempBksWithHolder(holder);

        CertificateValidator validate = new CertificateValidator(localization, holder);
        validate.invoke();

        assertThat(validate).isNotNull();
        assertThat(validate.getVerificationDetails()).isNotNull();
        assertThat(validate.getCertificateStatus())
                .isIn(CertificateStatus.TRUSTED, CertificateStatus.BROKEN, CertificateStatus.UNTRUSTED_ROOT);
        assertThat(validate.getCertificateChains()).isNotNull();
        assertThat(validate.getCertificateChains()).isNotEmpty();
    }

    @Test
    void validateIssuedCertWithoutChainInKeystore() throws Exception {
        X509CertificateHolder holder = TestCertUtils.loadHolderFromResources("1D13121735DD6E1F59EA58C786B8F7E8B7E6E20F.cer");

        Localization localization = new Localization();
        localization.TSL_LOCATION_BKS = TestCertUtils.createTempBksWithHolder(holder);

        CertificateValidator validate = new CertificateValidator(localization, holder);
        validate.invoke();

        assertThat(validate).isNotNull();
        assertThat(validate.getVerificationDetails()).isNotNull();
        assertThat(validate.getCertificateStatus())
                .isIn(CertificateStatus.UNTRUSTED_ROOT, CertificateStatus.BROKEN);
        assertThat(validate.getCertificateChains()).isNotNull();
        assertThat(validate.getCertificateChains()).isNotEmpty();
    }

    @Test
    void validatePopulatesChainDetails() throws Exception {
        X509CertificateHolder holder = TestCertUtils.loadHolderFromResources("2F0CB09BE3550EF17EC4F29C90ABD18BFCAAD63A.cer");

        Localization localization = new Localization();
        localization.TSL_LOCATION_BKS = TestCertUtils.createTempBksWithHolder(holder);

        CertificateValidator validate = new CertificateValidator(localization, holder);
        validate.invoke();

        for (CertificateModel.CertificateChain chain : validate.getCertificateChains()) {
            assertThat(chain.getCn()).isNotNull();
            assertThat(chain.getCertificateStatus()).isNotNull();
            assertThat(chain.getX509CertificateHolder()).isNotNull();
            assertThat(chain.getList()).isNotNull();
        }
    }

    @Test
    void validateBothResourceCerts() throws Exception {
        X509CertificateHolder selfSigned = TestCertUtils.loadHolderFromResources("2F0CB09BE3550EF17EC4F29C90ABD18BFCAAD63A.cer");
        X509CertificateHolder issued = TestCertUtils.loadHolderFromResources("1D13121735DD6E1F59EA58C786B8F7E8B7E6E20F.cer");

        Localization localization = new Localization();
        localization.TSL_LOCATION_BKS = TestCertUtils.createTempBksWithHolders(selfSigned, issued);

        CertificateValidator validateSelfSigned = new CertificateValidator(localization, selfSigned);
        validateSelfSigned.invoke();

        assertThat(validateSelfSigned.getCertificateStatus())
                .isIn(CertificateStatus.TRUSTED, CertificateStatus.BROKEN, CertificateStatus.UNTRUSTED_ROOT);

        CertificateValidator validateIssued = new CertificateValidator(localization, issued);
        validateIssued.invoke();

        assertThat(validateIssued.getCertificateStatus())
                .isIn(CertificateStatus.TRUSTED, CertificateStatus.BROKEN, CertificateStatus.UNTRUSTED_ROOT);
    }

    @Test
    void validateFedKaznacheistvoCert() throws Exception {
        X509CertificateHolder fkHolder = TestCertUtils.loadHolderFromResources("12BC42082D3F6027A29B7A87FE09B0329631C076.cer");
        X509CertificateHolder selfSignedHolder = TestCertUtils.loadHolderFromResources("2F0CB09BE3550EF17EC4F29C90ABD18BFCAAD63A.cer");

        Localization localization = new Localization();
        localization.TSL_LOCATION_BKS = TestCertUtils.createTempBksWithHolders(selfSignedHolder, fkHolder);

        CertificateValidator validate = new CertificateValidator(localization, fkHolder);
        validate.invoke();

        assertThat(validate).isNotNull();
        assertThat(validate.getVerificationDetails()).isNotNull();
        assertThat(validate.getCertificateStatus())
                .isIn(CertificateStatus.TRUSTED, CertificateStatus.BROKEN, CertificateStatus.UNTRUSTED_ROOT);
        assertThat(validate.getCertificateChains()).isNotNull();
        assertThat(validate.getCertificateChains()).isNotEmpty();
    }

    @Test
    void validateCrossCertWithIssuerInKeystore() throws Exception {
        X509CertificateHolder crossHolder = TestCertUtils.loadHolderFromResources("1D13121735DD6E1F59EA58C786B8F7E8B7E6E20F.cer");
        X509CertificateHolder selfSignedHolder = TestCertUtils.loadHolderFromResources("2F0CB09BE3550EF17EC4F29C90ABD18BFCAAD63A.cer");

        Localization localization = new Localization();
        localization.TSL_LOCATION_BKS = TestCertUtils.createTempBksWithHolders(selfSignedHolder, crossHolder);

        CertificateValidator validate = new CertificateValidator(localization, crossHolder);
        validate.invoke();

        assertThat(validate).isNotNull();
        assertThat(validate.getVerificationDetails()).isNotNull();
        assertThat(validate.getCertificateStatus())
                .isIn(CertificateStatus.TRUSTED, CertificateStatus.BROKEN, CertificateStatus.UNTRUSTED_ROOT);
        assertThat(validate.getCertificateChains()).isNotNull();
        assertThat(validate.getCertificateChains()).isNotEmpty();
    }
}
