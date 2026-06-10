package svkreml.certificateViewer.gui.view.utils;

import javafx.scene.control.Alert;
import javafx.scene.control.TextArea;

import java.io.PrintWriter;
import java.io.StringWriter;

public class Alerts {

    public static void showStackTraceAlert(Throwable e) {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setHeaderText(e.getMessage());
        StringWriter errors = new StringWriter();
        e.printStackTrace(new PrintWriter(errors));
        alert.setContentText(errors.toString());
        alert.show();
    }

    static public void showBigAlert(String textAreaText, Alert.AlertType alertType, String headerText) {
        TextArea textArea = new TextArea();
        textArea.setStyle("-fx-font-family: 'monospaced';");
        textArea.setText(textAreaText);

        textArea.setWrapText(true);
        textArea.setEditable(false);

        Alert alert = new Alert(alertType);
        alert.setResizable(true);
        alert.getDialogPane().setPrefSize(700, 750);
        alert.setHeaderText(headerText);

        alert.getDialogPane().setContent(textArea);
        alert.setResizable(true);
        alert.show();
    }

}
