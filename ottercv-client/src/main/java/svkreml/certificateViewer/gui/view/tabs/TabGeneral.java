package svkreml.certificateViewer.gui.view.tabs;

import javafx.scene.control.Label;
import javafx.scene.control.Tab;
import javafx.scene.layout.AnchorPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.scene.paint.Color;
import javafx.scene.shape.Circle;
import svkreml.certificateViewer.gui.api.model.CertificateModel;
import svkreml.certificateViewer.gui.api.model.CertificateStatus;
import svkreml.certificateViewer.gui.localization.ru.Localization;
import svkreml.certificateViewer.gui.view.utils.FxUtils;



public class TabGeneral {


    public static Tab create(Localization localization, CertificateModel certificateModel) {
        CertificateModel.CertificateGeneralInfo certificateGeneralInfo = certificateModel.certificateGeneralInfo;
        AnchorPane generalPane = new AnchorPane();
        Tab tabGeneral = new Tab(localization.TAB_GENERAL_TITLE, generalPane);
        tabGeneral.setClosable(false);


/*        ImageView certificateIcon = new ImageView();
        certificateIcon.setImage(new Image(
                new File("src/main/resources/svkreml/certificateViewer/certIcon.png").toURL().toString()));
        generalPane.getChildren().add(Utils.setAnchorPaneBorders(certificateIcon, 5.0, 30.0, null, null));*/

        FxUtils.createLabel(generalPane, localization.TAB_GENERAL_LABEL_CERTIFICATE_INFORMATION, 5.0, 5.0);

        FxUtils.createSeparator(generalPane, 90.0);
        Circle circle = new Circle(20);
        certificateGeneralInfo.certificateStatus.addListener((status)->{
            switch (certificateGeneralInfo.certificateStatus.getValue()) {
                case TRUSTED:
                    circle.setFill(Color.GREEN);
                    FxUtils.createLabel(generalPane, localization.nameCertificateStatus(CertificateStatus.TRUSTED), 100.0, 80.0);
                    break;
                case UNTRUSTED_ROOT:
                case UNTRUSTED_CHAIN:
                case BROKEN:
                case OVERDUE:
                    circle.setFill(Color.RED);
                    FxUtils.createLabel(generalPane, localization.nameCertificateStatus(certificateGeneralInfo.certificateStatus.getValue()), 100.0, 80.0);
                    break;
                case UNKNOWN:
                    circle.setFill(Color.GOLD);
                    FxUtils.createLabel(generalPane, localization.nameCertificateStatus(CertificateStatus.UNKNOWN), 100.0, 80.0);
                    break;
            }
        });


        VBox vbox = new VBox();
        FxUtils.setAnchorPaneBorders(vbox, 120.0, 90.0, 5.0, null);
        certificateGeneralInfo.statusDetails.addListener((statusDetails)->{
            for (String line : certificateGeneralInfo.statusDetails.getValue()) {
                Label lineLabel = new Label(line);
                vbox.getChildren().add(lineLabel);
            }
        });


        generalPane.getChildren().add(vbox);
        generalPane.getChildren().add( FxUtils.setAnchorPaneBorders(circle, 100.0, 30.0, null, null));
        FxUtils.createSeparator(generalPane, 350.0);
        FxUtils.createLabel(generalPane, localization.TAB_GENERAL_ISSUED_BY, 360.0, 40.0);
        FxUtils.createLabel(generalPane, certificateGeneralInfo.issuedTo, 360.0, 120.0);
        FxUtils.createLabel(generalPane, localization.TAB_GENERAL_ISSUED_TO, 400.0, 40.0);
        FxUtils.createLabel(generalPane, certificateGeneralInfo.issuedBy, 400.0, 120.0);


        HBox hBox = new HBox();
        hBox.getChildren().addAll(
                new Label(localization.TAB_GENERAL_VALID_FROM),
                new Label(localization.formatDate(certificateGeneralInfo.validFrom)),
                new Label(localization.TAB_GENERAL_VALID_TO),
                new Label(localization.formatDate(certificateGeneralInfo.validTo))
        );
        generalPane.getChildren().add(FxUtils.setAnchorPaneBorders(hBox, 440.0, 40.0, null, null));
        return tabGeneral;
    }
}
