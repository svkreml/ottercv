package svkreml.certificateViewer.gui;

import javafx.application.Application;
import javafx.application.Platform;
import javafx.geometry.Rectangle2D;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.Tab;
import javafx.scene.control.TabPane;
import javafx.scene.layout.AnchorPane;
import javafx.stage.Screen;
import javafx.stage.Stage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import svkreml.certificateViewer.gui.api.model.CertificateModel;
import svkreml.certificateViewer.gui.api.model.CertificateStatus;
import svkreml.certificateViewer.gui.certificateParser.CertificateParser;
import svkreml.certificateViewer.gui.localization.ru.Localization;
import svkreml.certificateViewer.gui.view.tabs.TabChain;
import svkreml.certificateViewer.gui.view.tabs.TabDetails;
import svkreml.certificateViewer.gui.view.tabs.TabGeneral;
import svkreml.certificateViewer.gui.view.utils.Alerts;
import svkreml.certificateViewer.gui.view.utils.FxUtils;
import svkreml.certificateViewer.gui.view.utils.Utils;

import java.io.IOException;
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


/*   sudo apt purge openjfx
    sudo  apt install openjfx=8u242-b08-0ubuntu3 libopenjfx-jni=8u242-b08-0ubuntu3 libopenjfx-java=8u242-b08-0ubuntu3
    sudo  apt-mark hold openjfx libopenjfx-jni libopenjfx-java*/

    // static String[] args;
    Localization localization;

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        //  APP.args = args;
        launch(args);
    }

    @Override
    public void start(Stage primaryStage) {
        try {
            localization = Localization.init();
            AnchorPane rootPane = createStage(primaryStage);
            Platform.runLater(() -> populateStage(rootPane));
        } catch (Throwable e) {
            Alerts.showStackTraceAlert(e);
        }
    }

    private void populateStage(AnchorPane rootPane) {
        final List<String> args = this.getParameters().getRaw();
            try {

                if (args.size() <= 0) {
                    System.exit(0);
                }
                byte[] certificateBytes = Files.readAllBytes(Paths.get(args.get(0)));

                certificateBytes = Utils.clearCertBytes(certificateBytes);
                X509CertificateHolder x509CertificateHolder = new X509CertificateHolder(certificateBytes);
                CertificateModel certificateModel = CertificateParser.getCertificateModel(localization, x509CertificateHolder);
                Platform.runLater(() -> {
                    Tab tabGeneral = TabGeneral.create(localization, certificateModel);
                    Tab tabDetails = TabDetails.create(localization, certificateModel);
                    Tab tabCertificationPath = TabChain.create(localization, certificateModel);
                    rootPane.getChildren().clear();
                    addTabs(tabGeneral, tabDetails, tabCertificationPath, rootPane);
                    buttonOk(rootPane);
                    Platform.runLater(() ->   validateCert(x509CertificateHolder, certificateModel));
                });
            } catch (Exception e) {
                Platform.runLater(() -> {
                    Alerts.showStackTraceAlert(e);
                });
            }
    }

    private void validateCert(X509CertificateHolder x509CertificateHolder, CertificateModel certificateModel) {
        try {
            CertificateParser.Validate validate = new CertificateParser.Validate(localization, x509CertificateHolder).invoke();

            List<String> verificationDetails = validate.getVerificationDetails();
            CertificateStatus certificateStatus = validate.getCertificateStatus();
            ArrayList<CertificateModel.CertificateChain> certificateChains = validate.getCertificateChains();

            Platform.runLater(() -> {
                certificateModel.getCertificateGeneralInfo().getCertificateStatus().setValue(certificateStatus);
                certificateModel.getCertificateGeneralInfo().getStatusDetails().setValue(verificationDetails);
                certificateModel.getCertificateChain().setValue(new ArrayList<>(new LinkedHashSet<>(certificateChains)));

            });
        } catch (CertificateException | NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException | IOException e) {
            Platform.runLater(() -> {
                Alerts.showStackTraceAlert(e);
            });
        }
    }


    private AnchorPane createStage(Stage primaryStage) {

        AnchorPane rootPane = new AnchorPane();
        rootPane.setPrefSize(500, 650);

        rootPane.getChildren().add(FxUtils.setAnchorPaneBorders(new Label(localization.LOADING), 20.0, 20.0, null, null));
        primaryStage.setMinWidth(500);
        primaryStage.setMinHeight(650);

        primaryStage.setMaxHeight(750);
        primaryStage.setMaxWidth(600);
        Scene scene = new Scene(rootPane, 500, 650);

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
        ok.setOnMouseClicked((e) -> {
            Platform.exit();
            System.exit(0);
        });
        rootPane.getChildren().add(ok);
    }
}
