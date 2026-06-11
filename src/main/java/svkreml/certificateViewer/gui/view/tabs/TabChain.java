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

    public static Tab create(Localization localization, CertificateModel certificateModel) {
        AnchorPane localRoot = new AnchorPane();
        Tab tabGeneral = new Tab(localization.TAB_CHAIN_TITLE, localRoot);
        tabGeneral.setClosable(false);
        FxUtils.createLabel(localRoot, localization.TAB_DETAILS_LABEL_CERTIFICATION_PATH, 5.0, 5.0);

        TextArea certStatusTextArea = new TextArea();
        certStatusTextArea.setEditable(false);
        certStatusTextArea.setStyle("-fx-font-family: 'monospaced';");
        TreeView<CertificateModel.CertificateChain> chainTree = new TreeView<>();
        chainTree.getSelectionModel().setSelectionMode(SelectionMode.SINGLE);

        chainTree.setCellFactory(param -> new TreeCell<>() {

            @Override
            public void updateItem(CertificateModel.CertificateChain item, boolean empty) {
                super.updateItem(item, empty);
                if (item == null || empty) {
                    setGraphic(null);
                    return;
                }
                HBox box = new HBox();
                box.setSpacing(5);
                Circle circle = new Circle(7);
                switch (item.certificateStatus) {
                    case TRUSTED -> circle.setFill(Color.GREEN);
                    case UNTRUSTED_ROOT, UNTRUSTED_CHAIN, BROKEN, OVERDUE -> circle.setFill(Color.RED);
                    case UNKNOWN -> circle.setFill(Color.GRAY);
                }
                box.getChildren().addAll(circle, new Label(item.getCn()));
                setGraphic(box);
            }
        });

        chainTree.setEditable(false);
        chainTree.setOnMouseClicked((e) -> {
            TreeItem<CertificateModel.CertificateChain> selectedItem =
                    chainTree.getSelectionModel().getSelectedItem();
            if (selectedItem == null || selectedItem.getValue() == null) return;
            CertificateModel.CertificateChain selectedCert = selectedItem.getValue();
            certStatusTextArea.setText(
                    localization.nameCertificateStatus(selectedCert.certificateStatus)
            );
            certStatusTextArea.appendText("\n----------------------------------------------\n");
            for (String s : selectedCert.getList()) {
                certStatusTextArea.appendText(s + "\n");
            }
        });


        certificateModel.certificateChain.addListener((chain) -> {
            TreeItem<CertificateModel.CertificateChain> currentRoot = null;
            for (int i = certificateModel.certificateChain.getValue().size() - 1; i >= 0; i--) {
                CertificateModel.CertificateChain model = certificateModel.certificateChain.getValue().get(i);
                if (currentRoot == null) {
                    currentRoot = new TreeItem<>(model);
                    currentRoot.addEventHandler(TreeItem.branchCollapsedEvent(),
                            (EventHandler<TreeItem.TreeModificationEvent<CertificateModel.CertificateChain>>) event -> event.getTreeItem()
                                    .setExpanded(true));
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
            var treeView = (TreeView<?>) rootPane.lookup("TreeView");
            @SuppressWarnings("unchecked")
            TreeItem<CertificateModel.CertificateChain> selected = (TreeItem<CertificateModel.CertificateChain>) treeView.getSelectionModel().getSelectedItem();
            if (selected != null && selected.getValue() != null) {
                try {
                    CertificateModel.CertificateChain selectedCert = selected.getValue();
                    Alerts.showBigAlert(
                            "-----BEGIN CERTIFICATE-----\n" +
                                    Base64.getMimeEncoder()
                                            .encodeToString(selectedCert.getX509CertificateHolder().getEncoded()) +
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
