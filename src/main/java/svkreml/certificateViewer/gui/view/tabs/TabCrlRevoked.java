package svkreml.certificateViewer.gui.view.tabs;

import javafx.collections.FXCollections;
import javafx.collections.transformation.FilteredList;
import javafx.geometry.Insets;
import javafx.geometry.Orientation;
import javafx.geometry.Pos;
import javafx.scene.control.Label;
import javafx.scene.control.SplitPane;
import javafx.scene.control.Tab;
import javafx.scene.control.TableCell;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import svkreml.certificateViewer.gui.api.model.CertificateModel;
import svkreml.certificateViewer.gui.api.model.CrlModel;
import svkreml.certificateViewer.gui.localization.ru.Localization;

import java.util.Date;
import java.util.Locale;
import java.util.StringJoiner;
import java.util.function.Predicate;

public class TabCrlRevoked {

    private static final String MONOSPACED_STYLE = "-fx-font-family: 'monospaced';";

    private TabCrlRevoked() {
    }

    public static Tab create(Localization localization, CrlModel crlModel) {
        VBox root = new VBox(8);
        root.setPadding(new Insets(5.0));
        Tab tab = new Tab(localization.TAB_CRL_REVOKED_TITLE, root);
        tab.setClosable(false);

        Label listLabel = new Label(localization.TAB_CRL_LABEL_REVOKED);
        listLabel.setWrapText(true);

        TextField serialFilter = new TextField();
        serialFilter.setPromptText(localization.TAB_CRL_FILTER_SERIAL_PROMPT);
        serialFilter.setPrefColumnCount(28);

        HBox filterBox = new HBox(8);
        filterBox.setAlignment(Pos.CENTER_LEFT);
        filterBox.getChildren().addAll(new Label(localization.TAB_CRL_FILTER_BY_SERIAL), serialFilter);

        TableView<CrlModel.RevokedCertificate> tableView = new TableView<>();
        tableView.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);

        FilteredList<CrlModel.RevokedCertificate> filteredCertificates =
                new FilteredList<>(FXCollections.observableArrayList(crlModel.getRevokedCertificates()),
                        certificate -> true);
        tableView.setItems(filteredCertificates);

        boolean hasRevokedCertificates = !crlModel.getRevokedCertificates().isEmpty();
        Runnable updatePlaceholder = () -> {
            boolean filterActive = !serialFilter.getText().isBlank();
            tableView.setPlaceholder(new Label(filterActive && hasRevokedCertificates
                    ? localization.TAB_CRL_NO_MATCHING_REVOKED
                    : localization.TAB_CRL_NO_REVOKED));
        };
        updatePlaceholder.run();

        serialFilter.textProperty().addListener((obs, oldValue, newValue) -> {
            filteredCertificates.setPredicate(serialNumberPredicate(newValue));
            updatePlaceholder.run();
        });

        TableColumn<CrlModel.RevokedCertificate, String> serialColumn =
                new TableColumn<>(localization.TAB_DETAIL_TABLE_KEY_SERIAL_NUMBER);
        serialColumn.setCellValueFactory(new PropertyValueFactory<>("serialNumber"));
        serialColumn.setPrefWidth(220);

        TableColumn<CrlModel.RevokedCertificate, Date> dateColumn =
                new TableColumn<>(localization.TAB_DETAIL_TABLE_KEY_REVOCATION_DATE);
        dateColumn.setCellValueFactory(new PropertyValueFactory<>("revocationDate"));
        dateColumn.setCellFactory(column -> new TableCell<>() {
            @Override
            protected void updateItem(Date item, boolean empty) {
                super.updateItem(item, empty);
                setText(empty || item == null ? null : localization.formatDate(item));
            }
        });
        dateColumn.setPrefWidth(150);

        TableColumn<CrlModel.RevokedCertificate, String> reasonColumn =
                new TableColumn<>(localization.TAB_DETAIL_TABLE_KEY_REVOCATION_REASON);
        reasonColumn.setCellValueFactory(new PropertyValueFactory<>("reason"));
        reasonColumn.setPrefWidth(160);

        TableColumn<CrlModel.RevokedCertificate, String> issuerColumn =
                new TableColumn<>(localization.TAB_DETAIL_TABLE_KEY_CERTIFICATE_ISSUER);
        issuerColumn.setCellValueFactory(new PropertyValueFactory<>("certificateIssuer"));
        issuerColumn.setPrefWidth(180);

        tableView.getColumns().addAll(serialColumn, dateColumn, reasonColumn, issuerColumn);

        TextArea detailsArea = new TextArea();
        detailsArea.setEditable(false);
        detailsArea.setWrapText(true);
        detailsArea.setStyle(MONOSPACED_STYLE);

        tableView.getSelectionModel().selectedItemProperty().addListener((obs, oldSelection, newSelection) -> {
            if (newSelection == null) {
                detailsArea.setText("");
                return;
            }
            detailsArea.setText(formatSelection(newSelection));
        });

        SplitPane splitPane = new SplitPane();
        splitPane.setOrientation(Orientation.VERTICAL);
        splitPane.setDividerPositions(0.65, 0.35);
        splitPane.getItems().addAll(tableView, detailsArea);
        VBox.setVgrow(splitPane, Priority.ALWAYS);

        root.getChildren().addAll(listLabel, filterBox, splitPane);
        return tab;
    }

    private static Predicate<CrlModel.RevokedCertificate> serialNumberPredicate(String query) {
        String normalizedQuery = normalizeSerialNumber(query);
        if (normalizedQuery.isEmpty()) {
            return certificate -> true;
        }
        return certificate -> normalizeSerialNumber(certificate.getSerialNumber()).contains(normalizedQuery);
    }

    private static String normalizeSerialNumber(String serialNumber) {
        if (serialNumber == null) {
            return "";
        }
        String normalized = serialNumber.trim().replaceAll("(?i)^0x", "")
                .replaceAll("[\\s:\\-]", "");
        return normalized.toUpperCase(Locale.ROOT);
    }

    private static String formatSelection(CrlModel.RevokedCertificate certificate) {
        StringJoiner joiner = new StringJoiner("\n");
        if (certificate.getDetails() != null) {
            for (CertificateModel.CertificateDetail detail : certificate.getDetails()) {
                joiner.add(detail.getField() + ": " + detail.getValue());
            }
        }
        return joiner.toString();
    }
}
