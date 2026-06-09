package svkreml.certificateViewer.gui.view.tabs;

import javafx.event.EventHandler;
import javafx.scene.control.*;
import javafx.scene.layout.AnchorPane;
import javafx.scene.layout.HBox;
import javafx.scene.paint.Color;
import javafx.scene.shape.Circle;
import svkreml.certificateViewer.gui.api.model.CertificateModel;
import svkreml.certificateViewer.gui.localization.ru.Localization;
import svkreml.certificateViewer.gui.view.utils.Alerts;
import svkreml.certificateViewer.gui.view.utils.FxUtils;

import java.util.Base64;

public class TabChain {

    static CertificateModel.CertificateChain selectedCert = null;

    public static Tab create(Localization localization, CertificateModel certificateModel) {
        AnchorPane localRoot = new AnchorPane();
        Tab tabGeneral = new Tab(localization.TAB_CHAIN_TITLE, localRoot);
        tabGeneral.setClosable(false);
        FxUtils.createLabel(localRoot, localization.TAB_DETAILS_LABEL_CERTIFICATION_PATH, 5.0, 5.0);

        TextArea certStatusTextArea = new TextArea();
        certStatusTextArea.setEditable(false);
        certStatusTextArea.setStyle("-fx-font-family: 'monospaced';");
        TreeView<CertificateModel.CertificateChain> chainTree = new TreeView<>();
        //chainTree.set(new PropertyValueFactory<>("fieldWithType"));
        chainTree.getSelectionModel().setSelectionMode(SelectionMode.SINGLE);

        chainTree.setCellFactory(param -> new TreeCell<CertificateModel.CertificateChain>() {

            @Override
            public void updateItem(CertificateModel.CertificateChain item, boolean empty) {
                if (item != null) {
                    HBox box = new HBox();
                    box.setSpacing(5);
                    Circle circle = new Circle(7);
                    switch (item.certificateStatus) {
                        case TRUSTED:
                            circle.setFill(Color.GREEN);
                            break;
                        case UNTRUSTED_ROOT:
                        case UNTRUSTED_CHAIN:
                        case BROKEN:
                        case OVERDUE:
                            circle.setFill(Color.RED);
                            break;
                        case UNKNOWN:
                            circle.setFill(Color.GRAY);
                            break;
                    }
                    box.getChildren().addAll(circle, new Label(item.getCn()));
                    setGraphic(box);

                }
                super.updateItem(item, empty);
            }
        });

        chainTree.setEditable(false);
        chainTree.setOnMouseClicked((e) -> {
            try {
                TreeItem<CertificateModel.CertificateChain> selectedItem = chainTree.getSelectionModel().getSelectedItem();
                selectedCert = selectedItem.getValue();
                certStatusTextArea.setText(
                        localization.nameCertificateStatus(selectedItem.getValue().certificateStatus)
                );
                certStatusTextArea.appendText("\n----------------------------------------------\n");
                for (String s : selectedItem.getValue().getList()) {
                    certStatusTextArea.appendText(s + "\n");
                }
            } catch (NullPointerException ignored) {
            }
        });


        certificateModel.certificateChain.addListener((chain)->{
            TreeItem<CertificateModel.CertificateChain> currentRoot = null;
            for (int i = certificateModel.certificateChain.getValue().size() - 1; i >= 0; i--) {
                CertificateModel.CertificateChain model = certificateModel.certificateChain.getValue().get(i);
                if (currentRoot == null) {
                    currentRoot = new TreeItem<>(model);
                    currentRoot.addEventHandler(TreeItem.branchCollapsedEvent(),
                            (EventHandler<TreeItem.TreeModificationEvent<CertificateModel.CertificateChain>>) event -> event.getTreeItem().setExpanded(true));
                    currentRoot.setExpanded(true);
                    chainTree.setRoot(currentRoot);
                } else {
                    TreeItem<CertificateModel.CertificateChain> newRoot = new TreeItem<>(model);
                    newRoot.setExpanded(true);
                    currentRoot.getChildren().add(newRoot);
                    currentRoot = newRoot;
                }
            }
        });

        localRoot.getChildren().add(FxUtils.setAnchorPaneBorders(chainTree, 25.0, 5.0, 5.0, null));
        localRoot.getChildren().add(FxUtils.setAnchorPaneBorders(certStatusTextArea, null, 5.0, 5.0, 45.0));

        buttonBase64(localization, localRoot);

        return tabGeneral;
    }

    private static void buttonBase64(Localization localization, AnchorPane rootPane) {
        Button button = new Button(localization.BUTTON_TO_BASE64);
        FxUtils.setAnchorPaneBorders(button, null, null, 5.0, 10.0);
        button.setCancelButton(true);
        button.setOnMouseClicked((e) -> {
            if (selectedCert != null) {
                try {
                    Alerts.showBigAlert(
                            "-----BEGIN CERTIFICATE-----\n" +
                                    Base64.getMimeEncoder().encodeToString(selectedCert.getX509CertificateHolder().getEncoded()) +
                                    "\n-----END CERTIFICATE-----",
                            Alert.AlertType.INFORMATION, selectedCert.getCn());
                } catch (Exception ex) {
                    Alerts.showStackTraceAlert(ex);
                }
            }
        });
        rootPane.getChildren().add(button);
    }

}
