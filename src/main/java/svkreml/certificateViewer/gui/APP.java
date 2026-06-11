package svkreml.certificateViewer.gui;

import javafx.application.Application;
import javafx.application.Platform;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.Tab;
import javafx.scene.control.TabPane;
import javafx.scene.layout.AnchorPane;
import javafx.stage.Stage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import svkreml.certificateViewer.gui.api.model.CertificateModel;
import svkreml.certificateViewer.gui.api.model.CertificateStatus;
import svkreml.certificateViewer.gui.certificateParser.CertificateParser;
import svkreml.certificateViewer.gui.certificateParser.CertificateValidator;
import svkreml.certificateViewer.gui.localization.ru.Localization;
import svkreml.certificateViewer.gui.view.tabs.TabChain;
import svkreml.certificateViewer.gui.view.tabs.TabDetails;
import svkreml.certificateViewer.gui.view.tabs.TabGeneral;
import svkreml.certificateViewer.gui.view.utils.Alerts;
import svkreml.certificateViewer.gui.view.utils.FxUtils;
import svkreml.certificateViewer.gui.view.utils.Utils;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;


public class APP extends Application {

    private static final int WINDOW_WIDTH = 500;
    private static final int WINDOW_HEIGHT = 650;
    private static final int WINDOW_MIN_WIDTH = 600;
    private static final int WINDOW_MIN_HEIGHT = 750;
    private static final int WINDOW_MAX_WIDTH = 600;
    private static final int WINDOW_MAX_HEIGHT = 750;
    private static final Logger log = LoggerFactory.getLogger(APP.class);

    Localization localization;

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        launch(args);
    }

    @Override
    public void start(Stage primaryStage) {
        try {
            localization = Localization.init();
            AnchorPane rootPane = createStage(primaryStage);
            Platform.runLater(() -> populateStage(rootPane));
        } catch (Exception e) {
            Alerts.showStackTraceAlert(e);
            log.error(e.getMessage(), e);
        }
    }

    private void populateStage(AnchorPane rootPane) {
        final List<String> args = this.getParameters().getRaw();
        try {
            byte[] certificateBytes;
            if (args.isEmpty()) {
                try (InputStream is = getClass().getResourceAsStream("/certs/default.pem")) {
                    certificateBytes = java.util.Objects.requireNonNull(is, "default.pem not found on classpath").readAllBytes();
                }
            } else {
                certificateBytes = Files.readAllBytes(Paths.get(args.getFirst()));
            }
            certificateBytes = Utils.clearCertBytes(certificateBytes);
            X509CertificateHolder x509CertificateHolder = new X509CertificateHolder(certificateBytes);
            CertificateModel
                    certificateModel =
                    CertificateParser.getCertificateModel(localization, x509CertificateHolder);
            Platform.runLater(() -> {
                Tab tabGeneral = TabGeneral.create(localization, certificateModel);
                Tab tabDetails = TabDetails.create(localization, certificateModel);
                Tab tabCertificationPath = TabChain.create(localization, certificateModel);
                rootPane.getChildren().clear();
                addTabs(tabGeneral, tabDetails, tabCertificationPath, rootPane);
                buttonOk(rootPane);
                Platform.runLater(() -> validateCert(x509CertificateHolder, certificateModel));
            });
        } catch (Exception e) {
            Platform.runLater(() -> Alerts.showStackTraceAlert(e));
        }
    }

    public void validateCert(X509CertificateHolder x509CertificateHolder, CertificateModel certificateModel) {
        try {
            log.info("Validating cert subject={}", x509CertificateHolder.getSubject());
            CertificateValidator
                    validator =
                    new CertificateValidator(localization, x509CertificateHolder).invoke();

            List<String> verificationDetails = validator.getVerificationDetails();
            CertificateStatus certificateStatus = validator.getCertificateStatus();
            log.info("Validation result: status={}, details={}", certificateStatus, verificationDetails);
            ArrayList<CertificateModel.CertificateChain> certificateChains = validator.getCertificateChains();

            Platform.runLater(() -> {
                certificateModel.getCertificateGeneralInfo().getCertificateStatus().setValue(certificateStatus);
                certificateModel.getCertificateGeneralInfo().getStatusDetails().setValue(verificationDetails);
                certificateModel.getCertificateChain()
                        .setValue(new ArrayList<>(new LinkedHashSet<>(certificateChains)));

            });
        } catch (CertificateException |
                 NoSuchAlgorithmException |
                 NoSuchProviderException |
                 InvalidAlgorithmParameterException |
                 IOException e) {
            Platform.runLater(() -> Alerts.showStackTraceAlert(e));
        }
    }

    private AnchorPane createStage(Stage primaryStage) {

        AnchorPane rootPane = new AnchorPane();
        rootPane.setPrefSize(WINDOW_WIDTH, WINDOW_HEIGHT);

        rootPane.getChildren()
                .add(FxUtils.setAnchorPaneBorders(new Label(localization.LOADING), 20.0, 20.0, null, null));
        primaryStage.setMinWidth(WINDOW_MIN_WIDTH);
        primaryStage.setMinHeight(WINDOW_MIN_HEIGHT);

        primaryStage.setMaxHeight(WINDOW_MAX_HEIGHT);
        primaryStage.setMaxWidth(WINDOW_MAX_WIDTH);
        Scene scene = new Scene(rootPane, WINDOW_WIDTH, WINDOW_HEIGHT);

        primaryStage.setScene(scene);
        primaryStage.setTitle(localization.PROGRAM_TITLE);
        primaryStage.show();

        return rootPane;
    }

    private void addTabs(Tab tabGeneral, Tab tabDetails, Tab tabCertificationPath, AnchorPane rootPane) {
        TabPane tabPane = new TabPane();
        tabPane.getTabs().addAll(
                tabGeneral,
                tabDetails,
                tabCertificationPath);
        rootPane.getChildren().add(FxUtils.setAnchorPaneBorders(tabPane, 2.0, 2.0, 2.0, 60.0));

    }

    private void buttonOk(AnchorPane rootPane) {
        Button ok = new Button(localization.BUTTON_OK);
        FxUtils.setAnchorPaneBorders(ok, null, null, 10.0, 10.0);
        ok.setCancelButton(true);
        ok.setOnMouseClicked((e) -> Platform.exit());
        rootPane.getChildren().add(ok);
    }
}
