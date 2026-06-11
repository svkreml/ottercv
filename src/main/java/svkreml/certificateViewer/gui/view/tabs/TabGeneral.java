package svkreml.certificateViewer.gui.view.tabs;

import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.Label;
import javafx.scene.control.Separator;
import javafx.scene.control.Tab;
import javafx.scene.control.TextArea;
import javafx.scene.layout.*;
import javafx.scene.paint.Color;
import javafx.scene.shape.Circle;
import svkreml.certificateViewer.gui.api.model.CertificateModel;
import svkreml.certificateViewer.gui.api.model.CertificateStatus;
import svkreml.certificateViewer.gui.localization.ru.Localization;

import java.util.StringJoiner;

public class TabGeneral {

    private static final String STATUS_FONT = "-fx-font-weight: bold; -fx-font-size: 13px;";
    private static final String LABEL_FONT = "-fx-font-size: 12px;";
    private static final String VALUE_FONT = "-fx-font-size: 12px; -fx-font-weight: bold;";
    private static final String DETAILS_FONT = "-fx-font-family: 'monospaced'; -fx-font-size: 11px;";
    private static final String TITLE_FONT = "-fx-font-size: 14px; -fx-font-weight: bold;";
    private static final String BG_COLOR = "#f8f9fa";
    private static final String BORDER_COLOR = "#ced4da";
    private static final String TRUSTED_COLOR = "#1a7f37";
    private static final String BROKEN_COLOR = "#c92a2a";
    private static final String UNKNOWN_COLOR = "#e67700";

    public static Tab create(Localization localization, CertificateModel certificateModel) {
        CertificateModel.CertificateGeneralInfo certificateGeneralInfo = certificateModel.certificateGeneralInfo;
        VBox root = new VBox(10);
        root.setPadding(new Insets(12));
        root.setBackground(new Background(new BackgroundFill(Color.web(BG_COLOR), CornerRadii.EMPTY, Insets.EMPTY)));

        Tab tabGeneral = new Tab(localization.TAB_GENERAL_TITLE, root);
        tabGeneral.setClosable(false);

        Label titleLabel = new Label(localization.TAB_GENERAL_LABEL_CERTIFICATE_INFORMATION);
        titleLabel.setStyle(TITLE_FONT);
        root.getChildren().add(titleLabel);

        Separator sep1 = new Separator();
        root.getChildren().add(sep1);

        HBox statusBox = new HBox(12);
        statusBox.setAlignment(Pos.CENTER_LEFT);
        statusBox.setPadding(new Insets(10, 0, 10, 5));

        Circle circle = new Circle(14);
        Label statusLabel = new Label();
        statusLabel.setStyle(STATUS_FONT);
        statusLabel.setMaxWidth(Double.MAX_VALUE);
        HBox.setHgrow(statusLabel, Priority.ALWAYS);

        certificateGeneralInfo.certificateStatus.addListener((status) -> {
            switch (certificateGeneralInfo.certificateStatus.getValue()) {
                case TRUSTED:
                    circle.setFill(Color.GREEN);
                    statusLabel.setText(localization.nameCertificateStatus(CertificateStatus.TRUSTED));
                    statusLabel.setTextFill(Color.web(TRUSTED_COLOR));
                    break;
                case UNTRUSTED_ROOT:
                case UNTRUSTED_CHAIN:
                case BROKEN:
                case OVERDUE:
                    circle.setFill(Color.RED);
                    statusLabel.setText(localization.nameCertificateStatus(certificateGeneralInfo.certificateStatus.getValue()));
                    statusLabel.setTextFill(Color.web(BROKEN_COLOR));
                    break;
                case UNKNOWN:
                    circle.setFill(Color.GOLD);
                    statusLabel.setText(localization.nameCertificateStatus(CertificateStatus.UNKNOWN));
                    statusLabel.setTextFill(Color.web(UNKNOWN_COLOR));
                    break;
            }
        });

        statusBox.getChildren().addAll(circle, statusLabel);
        root.getChildren().add(statusBox);

        TextArea detailsArea = new TextArea();
        detailsArea.setEditable(false);
        detailsArea.setWrapText(true);
        detailsArea.setStyle(DETAILS_FONT);
        detailsArea.setBackground(new Background(new BackgroundFill(Color.WHITE, CornerRadii.EMPTY, Insets.EMPTY)));
        detailsArea.setBorder(new Border(new BorderStroke(Color.web(BORDER_COLOR),
                BorderStrokeStyle.SOLID,
                new CornerRadii(4),
                new BorderWidths(1))));
        detailsArea.setPrefRowCount(8);
        detailsArea.setPadding(new Insets(8));

        certificateGeneralInfo.statusDetails.addListener((statusDetails) -> {
            StringJoiner joiner = new StringJoiner("\n");
            for (String line : certificateGeneralInfo.statusDetails.getValue()) {
                joiner.add(line);
            }
            detailsArea.setText(joiner.toString());
        });

        root.getChildren().add(detailsArea);

        Separator sep2 = new Separator();
        root.getChildren().add(sep2);

        GridPane infoGrid = new GridPane();
        infoGrid.setHgap(15);
        infoGrid.setVgap(8);
        infoGrid.setPadding(new Insets(5, 0, 5, 0));

        Label issuedByLabel = new Label(localization.TAB_GENERAL_ISSUED_BY);
        issuedByLabel.setStyle(LABEL_FONT);
        Label issuedToLabel = new Label(localization.TAB_GENERAL_ISSUED_TO);
        issuedToLabel.setStyle(LABEL_FONT);

        ColumnConstraints col1 = new ColumnConstraints();
        col1.setMinWidth(100);
        ColumnConstraints col2 = new ColumnConstraints();
        col2.setHgrow(Priority.ALWAYS);

        infoGrid.getColumnConstraints().addAll(col1, col2);

        infoGrid.add(issuedByLabel, 0, 0);
        Label issuedByValue = new Label(certificateGeneralInfo.issuedTo);
        issuedByValue.setStyle(VALUE_FONT);
        issuedByValue.setWrapText(true);
        infoGrid.add(issuedByValue, 1, 0);

        infoGrid.add(issuedToLabel, 0, 1);
        Label issuedToValue = new Label(certificateGeneralInfo.issuedBy);
        issuedToValue.setStyle(VALUE_FONT);
        issuedToValue.setWrapText(true);
        infoGrid.add(issuedToValue, 1, 1);

        root.getChildren().add(infoGrid);

        HBox dateBox = new HBox(8);
        dateBox.setAlignment(Pos.CENTER_LEFT);
        dateBox.setPadding(new Insets(5, 0, 0, 0));

        Label validFromLabel = new Label(localization.TAB_GENERAL_VALID_FROM);
        validFromLabel.setStyle(LABEL_FONT);
        Label validFromValue = new Label(localization.formatDate(certificateGeneralInfo.validFrom));
        validFromValue.setStyle(VALUE_FONT);

        Label validToLabel = new Label(localization.TAB_GENERAL_VALID_TO);
        validToLabel.setStyle(LABEL_FONT);
        Label validToValue = new Label(localization.formatDate(certificateGeneralInfo.validTo));
        validToValue.setStyle(VALUE_FONT);

        dateBox.getChildren().addAll(validFromLabel, validFromValue, validToLabel, validToValue);
        root.getChildren().add(dateBox);

        return tabGeneral;
    }
}
