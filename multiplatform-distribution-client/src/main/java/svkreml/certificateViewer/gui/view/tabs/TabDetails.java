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
        TableColumn<CertificateModel.CertificateDetail, Pair<String, DetailType>> columnKey = new TableColumn<>("field");
        columnKey.setSortable(false);

        columnKey.setCellFactory(param -> new TableCell<CertificateModel.CertificateDetail, Pair<String, DetailType>>() {

            @Override
            public void updateItem(Pair<String, DetailType> item, boolean empty) {
                if (item != null) {
                    this.setTooltip(new Tooltip(item.getKey()));
                    HBox box = new HBox();
                    box.setSpacing(5);
                    Circle circle = new Circle(7);
                    //Sphere sphere = new Sphere(10);
                    PhongMaterial material = new PhongMaterial();
                    switch (item.getValue()) {
                        case PROP:
                            circle.setFill(Color.GRAY);
                            //   material.setDiffuseColor(Color.rgb(255, 60, 30));
                            //   material.setSpecularColor(Color.rgb(255, 60, 30));
                            break;
                        case CRIT_EXT:
                            circle.setFill(Color.RED);
                            //   material.setDiffuseColor(Color.rgb(200, 30, 200));
                            //   material.setSpecularColor(Color.rgb(200, 30, 200));
                            break;
                        case NON_CRIT_EXT:
                            circle.setFill(Color.DARKRED);
                            //   material.setDiffuseColor(Color.rgb(30, 200, 200));
                            //   material.setSpecularColor(Color.rgb(30, 200, 200));
                            break;
                        case THUMBPRINT:
                            circle.setFill(Color.DARKGREEN);
                            //   material.setDiffuseColor(Color.rgb(200, 200, 30));
                            //    material.setSpecularColor(Color.rgb(200, 200, 30));
                            break;
                    }

                    //sphere.setMaterial(material);
/*                                ImageView imageview = new ImageView();
                    imageview.setFitHeight(50);
                    imageview.setFitWidth(50);
                    imageview.setImage(new Image("="));*/
                    box.getChildren().addAll(circle, new Label(item.getKey()));
                    //SETTING ALL THE GRAPHICS COMPONENT FOR CELL
                    setGraphic(box);
                }
                super.updateItem(item, empty);
            }
        });

        columnKey.setCellValueFactory(new PropertyValueFactory<>("fieldWithType"));
        columnKey.setMinWidth(30);
        columnKey.setPrefWidth(80);
        columnKey.setPrefWidth(200);
        tableView.getColumns().add(columnKey);

        TableColumn<CertificateModel.CertificateDetail, String> columnValue = new TableColumn<>("value");
        columnValue.setSortable(false);
        columnValue.setCellValueFactory(new PropertyValueFactory<>("valueOneLine"));
        columnValue.setPrefWidth(200);
        tableView.getColumns().add(columnValue);

        tableView.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY);
        TextArea certStatusTextArea = new TextArea(); //TODO хранилище текстов
        //  certStatusTextArea.setFont(new Font( "Mono", 14));
        certStatusTextArea.setStyle("-fx-font-family: 'monospaced';");
        certStatusTextArea.setEditable(false);
        certStatusTextArea.setWrapText(true);
        tableView.getSelectionModel().selectedItemProperty().addListener((obs, oldSelection, newSelection) -> {
            if (newSelection != null) {
                certStatusTextArea.setText(newSelection.getDetail() != null ? newSelection.getDetail() : newSelection.getValue());
            } else {
                certStatusTextArea.setText("");
            }
        });
/*        columnKey.minWidthProperty().set(75);
        columnKey.prefWidthProperty().set(100);
        columnKey.maxWidthProperty().set(500);

        columnValue.minWidthProperty().set(100);
        columnValue.prefWidthProperty().set(400);
        columnValue.maxWidthProperty().set(500);*/

        tableView.getItems().addAll(certificateModel.certificateDetails);

        SplitPane splitPane = new SplitPane();
        splitPane.setOrientation(Orientation.VERTICAL);
        splitPane.setDividerPositions(0.75, 0.25);
        splitPane.getItems().add(tableView);
        splitPane.getItems().add(certStatusTextArea);

        localRoot.getChildren().add(FxUtils.setAnchorPaneBorders(splitPane, 25.0, 5.0, 5.0, 20.0));
        //  tab.setContent(splitPane);
        return tab;
    }

}
