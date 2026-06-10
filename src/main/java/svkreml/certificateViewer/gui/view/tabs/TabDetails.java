package svkreml.certificateViewer.gui.view.tabs;


import javafx.geometry.Orientation;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.layout.AnchorPane;
import javafx.scene.layout.HBox;
import javafx.scene.paint.Color;
import javafx.scene.paint.PhongMaterial;
import javafx.scene.shape.Circle;
import javafx.util.Pair;
import svkreml.certificateViewer.gui.api.model.CertificateModel;
import svkreml.certificateViewer.gui.api.model.DetailType;
import svkreml.certificateViewer.gui.localization.ru.Localization;
import svkreml.certificateViewer.gui.view.utils.FxUtils;

public class TabDetails {

    public static Tab create(Localization localization, CertificateModel certificateModel) {
        AnchorPane localRoot = new AnchorPane();
        Tab tab = new Tab(localization.TAB_DETAILS_TITLE, localRoot);
        tab.setClosable(false);
        FxUtils.createLabel(localRoot, localization.TAB_DETAILS_LABEL_SHOW, 5.0, 5.0);

        TableView<CertificateModel.CertificateDetail> tableView = new TableView<>();
        final TableColumn<CertificateModel.CertificateDetail, Pair<String, DetailType>> columnKey = getCertificateDetailPairTableColumn();
        tableView.getColumns().add(columnKey);

        TableColumn<CertificateModel.CertificateDetail, String> columnValue = new TableColumn<>("value");
        columnValue.setSortable(false);
        columnValue.setCellValueFactory(new PropertyValueFactory<>("valueOneLine"));
        columnValue.setPrefWidth(200);
        tableView.getColumns().add(columnValue);

        tableView.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);
        TextArea certStatusTextArea = new TextArea();
        certStatusTextArea.setStyle("-fx-font-family: 'monospaced';");
        certStatusTextArea.setEditable(false);
        certStatusTextArea.setWrapText(true);
        tableView.getSelectionModel().selectedItemProperty().addListener((obs, oldSelection, newSelection) -> {
            if (newSelection != null) {
                certStatusTextArea.setText(newSelection.getDetail() != null ?
                        newSelection.getDetail() :
                        newSelection.getValue());
            } else {
                certStatusTextArea.setText("");
            }
        });

        tableView.getItems().addAll(certificateModel.certificateDetails);

        SplitPane splitPane = new SplitPane();
        splitPane.setOrientation(Orientation.VERTICAL);
        splitPane.setDividerPositions(0.75, 0.25);
        splitPane.getItems().add(tableView);
        splitPane.getItems().add(certStatusTextArea);

        localRoot.getChildren().add(FxUtils.setAnchorPaneBorders(splitPane, 25.0, 5.0, 5.0, 20.0));
        return tab;
    }

    private static TableColumn<CertificateModel.CertificateDetail, Pair<String, DetailType>> getCertificateDetailPairTableColumn() {
        TableColumn<CertificateModel.CertificateDetail, Pair<String, DetailType>>
                columnKey =
                new TableColumn<>("field");
        columnKey.setSortable(false);

        columnKey.setCellFactory(param -> new TableCell<>() {

            @Override
            public void updateItem(Pair<String, DetailType> item, boolean empty) {
                if (item != null) {
                    this.setTooltip(new Tooltip(item.getKey()));
                    HBox box = new HBox();
                    box.setSpacing(5);
                    Circle circle = new Circle(7);
                    switch (item.getValue()) {
                        case PROP:
                            circle.setFill(Color.GRAY);
                            break;
                        case CRIT_EXT:
                            circle.setFill(Color.RED);
                            break;
                        case NON_CRIT_EXT:
                            circle.setFill(Color.DARKRED);
                            break;
                        case THUMBPRINT:
                            circle.setFill(Color.DARKGREEN);
                            break;
                    }
                    box.getChildren().addAll(circle, new Label(item.getKey()));
                    setGraphic(box);
                }
                super.updateItem(item, empty);
            }
        });

        columnKey.setCellValueFactory(new PropertyValueFactory<>("fieldWithType"));
        columnKey.setMinWidth(30);
        columnKey.setPrefWidth(80);
        columnKey.setPrefWidth(200);
        return columnKey;
    }

}
