package svkreml.certificateViewer.gui.view.tabs;

import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.Label;
import javafx.scene.control.Separator;
import javafx.scene.control.Tab;
import javafx.scene.control.TextArea;
import javafx.scene.layout.Background;
import javafx.scene.layout.BackgroundFill;
import javafx.scene.layout.Border;
import javafx.scene.layout.BorderStroke;
import javafx.scene.layout.BorderStrokeStyle;
import javafx.scene.layout.BorderWidths;
import javafx.scene.layout.ColumnConstraints;
import javafx.scene.layout.CornerRadii;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.scene.paint.Color;
import javafx.scene.shape.Circle;
import svkreml.certificateViewer.gui.api.model.CrlModel;
import svkreml.certificateViewer.gui.api.model.CrlStatus;
import svkreml.certificateViewer.gui.localization.ru.Localization;

import java.util.StringJoiner;

public class TabCrlGeneral {

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

    private TabCrlGeneral() {
    }

    public static Tab create(Localization localization, CrlModel crlModel) {
        CrlModel.CrlGeneralInfo generalInfo = crlModel.getGeneralInfo();
        VBox root = new VBox(10);
        root.setPadding(new Insets(12));
        root.setBackground(new Background(new BackgroundFill(Color.web(BG_COLOR), CornerRadii.EMPTY, Insets.EMPTY)));

        Tab tabGeneral = new Tab(localization.TAB_GENERAL_TITLE, root);
        tabGeneral.setClosable(false);

        Label titleLabel = new Label(localization.TAB_GENERAL_LABEL_CRL_INFORMATION);
        titleLabel.setStyle(TITLE_FONT);
        root.getChildren().add(titleLabel);

        root.getChildren().add(new Separator());

        HBox statusBox = new HBox(12);
        statusBox.setAlignment(Pos.CENTER_LEFT);
        statusBox.setPadding(new Insets(10, 0, 10, 5));

        Circle circle = new Circle(14);
        Label statusLabel = new Label();
        statusLabel.setStyle(STATUS_FONT);
        statusLabel.setMaxWidth(Double.MAX_VALUE);
        HBox.setHgrow(statusLabel, Priority.ALWAYS);
        statusBox.getChildren().addAll(circle, statusLabel);
        root.getChildren().add(statusBox);

        Runnable updateStatus = () -> updateStatus(localization, generalInfo, circle, statusLabel);
        updateStatus.run();
        generalInfo.getStatus().addListener((obs, oldValue, newValue) -> updateStatus.run());

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

        Runnable updateDetails = () -> detailsArea.setText(joinDetails(generalInfo));
        updateDetails.run();
        generalInfo.getStatusDetails().addListener((obs, oldValue, newValue) -> updateDetails.run());
        root.getChildren().add(detailsArea);

        root.getChildren().add(new Separator());

        GridPane infoGrid = new GridPane();
        infoGrid.setHgap(15);
        infoGrid.setVgap(8);
        infoGrid.setPadding(new Insets(5, 0, 5, 0));

        ColumnConstraints col1 = new ColumnConstraints();
        col1.setMinWidth(150);
        ColumnConstraints col2 = new ColumnConstraints();
        col2.setHgrow(Priority.ALWAYS);
        infoGrid.getColumnConstraints().addAll(col1, col2);

        int row = 0;
        addInfoRow(infoGrid, row++, localization.TAB_GENERAL_CRL_ISSUER, generalInfo.getIssuer());
        addInfoRow(infoGrid, row++, localization.TAB_GENERAL_CRL_VERSION, generalInfo.getVersion());
        addInfoRow(infoGrid, row++, localization.TAB_GENERAL_CRL_SIGNATURE_ALG, generalInfo.getSignatureAlgorithm());
        addInfoRow(infoGrid, row++, localization.TAB_GENERAL_CRL_NUMBER,
                generalInfo.getCrlNumber() != null ? generalInfo.getCrlNumber() : localization.NOT_AVAILABLE);
        addInfoRow(infoGrid, row, localization.TAB_GENERAL_CRL_REVOKED_COUNT,
                String.valueOf(generalInfo.getRevokedCount()));
        root.getChildren().add(infoGrid);

        HBox dateBox = new HBox(8);
        dateBox.setAlignment(Pos.CENTER_LEFT);
        dateBox.setPadding(new Insets(5, 0, 0, 0));

        Label thisUpdateLabel = new Label(localization.TAB_GENERAL_CRL_THIS_UPDATE);
        thisUpdateLabel.setStyle(LABEL_FONT);
        Label thisUpdateValue = new Label(localization.formatDate(generalInfo.getThisUpdate()));
        thisUpdateValue.setStyle(VALUE_FONT);

        Label nextUpdateLabel = new Label(localization.TAB_GENERAL_CRL_NEXT_UPDATE);
        nextUpdateLabel.setStyle(LABEL_FONT);
        Label nextUpdateValue = new Label(generalInfo.getNextUpdate() != null
                ? localization.formatDate(generalInfo.getNextUpdate())
                : localization.NOT_AVAILABLE);
        nextUpdateValue.setStyle(VALUE_FONT);

        dateBox.getChildren().addAll(
                thisUpdateLabel, thisUpdateValue,
                nextUpdateLabel, nextUpdateValue);
        root.getChildren().add(dateBox);

        return tabGeneral;
    }

    private static void updateStatus(Localization localization,
                                     CrlModel.CrlGeneralInfo generalInfo,
                                     Circle circle,
                                     Label statusLabel) {
        CrlStatus status = generalInfo.getStatus().getValue();
        if (status == null) {
            status = CrlStatus.UNKNOWN;
        }
        statusLabel.setText(localization.nameCrlStatus(status));
        switch (status) {
            case VALID -> {
                circle.setFill(Color.GREEN);
                statusLabel.setTextFill(Color.web(TRUSTED_COLOR));
            }
            case EXPIRED, SIGNATURE_INVALID -> {
                circle.setFill(Color.RED);
                statusLabel.setTextFill(Color.web(BROKEN_COLOR));
            }
            case NOT_YET_VALID, ISSUER_NOT_FOUND -> {
                circle.setFill(Color.GOLD);
                statusLabel.setTextFill(Color.web(UNKNOWN_COLOR));
            }
            case UNKNOWN -> {
                circle.setFill(Color.GRAY);
                statusLabel.setTextFill(Color.GRAY);
            }
        }
    }

    private static String joinDetails(CrlModel.CrlGeneralInfo generalInfo) {
        StringJoiner joiner = new StringJoiner("\n");
        if (generalInfo.getStatusDetails().getValue() != null) {
            for (String line : generalInfo.getStatusDetails().getValue()) {
                joiner.add(line);
            }
        }
        return joiner.toString();
    }

    private static void addInfoRow(GridPane grid, int row, String labelText, String valueText) {
        Label label = new Label(labelText);
        label.setStyle(LABEL_FONT);
        Label value = new Label(valueText);
        value.setStyle(VALUE_FONT);
        value.setWrapText(true);
        grid.add(label, 0, row);
        grid.add(value, 1, row);
    }
}
