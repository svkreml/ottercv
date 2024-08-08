package svkreml.certificateViewer.gui.view.utils;

import javafx.scene.control.Alert;
import javafx.scene.control.ButtonType;
import javafx.scene.control.TextArea;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Optional;

public class Alerts {
    public static void showSimpleAlert(Alert.AlertType alertType, String headerText, String contentText){
        Alert alert = new Alert(alertType);
        alert.setHeaderText(headerText);
        alert.setContentText(contentText);
        alert.show();
    }
    public static void showStackTraceAlert(Throwable e){
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setHeaderText(e.getMessage());
        StringWriter errors = new StringWriter();
        e.printStackTrace(new PrintWriter(errors));
        alert.setContentText(errors.toString());
        alert.show();
    }


    public static boolean showSimpleAlertQuestion(Alert.AlertType alertType, String headerText, String contentText) {
        Alert alert = new Alert(alertType);

        alert.setHeaderText(headerText);
        alert.setContentText(contentText);


        final Optional<ButtonType> buttonType = alert.showAndWait();
        return buttonType.filter(type -> type == ButtonType.OK).isPresent();
    }

    public static String showAlertQuestion(Alert.AlertType alertType, String headerText, String promptText, String textAreaText) {
        Alert alert = new Alert(alertType);

        TextArea textArea = new TextArea();
        textArea.setStyle("-fx-font-family: 'monospaced';");

        textArea.setWrapText(true);
        textArea.setEditable(true);

        textArea.setPromptText(promptText);

        if(textAreaText != null)
            textArea.setText(textAreaText);

        alert.setHeaderText(headerText);

        alert.setContentText(promptText);
        alert.getDialogPane().setContent(textArea);
        alert.setResizable(true);
        final Optional<ButtonType> buttonType = alert.showAndWait();
        if (buttonType.isPresent()) {
            if (buttonType.get() == ButtonType.OK)
                return textArea.getText();
            else return null;
        } else return null;
    }


    static public void showBigAlert(String textAreaText, Alert.AlertType alertType, String headerText) {
        TextArea textArea = new TextArea();
        textArea.setStyle("-fx-font-family: 'monospaced';");
        textArea.setText(textAreaText);

        textArea.setWrapText(true);
        textArea.setEditable(false);


        Alert alert = new Alert(alertType);
        alert.setResizable(true);
/*        alert.getDialogPane().setMaxHeight(700);
        alert.getDialogPane().setMinHeight(700);
        alert.getDialogPane().setMaxWidth(700);*/
        alert.getDialogPane().setPrefSize(700, 750);
        alert.setHeaderText(headerText);


        alert.getDialogPane().setContent(textArea);
        alert.setResizable(true);
        alert.show();
    }


/*    static public void showBigAlertForInput(String textAreaText, Alert.AlertType alertType, String headerText) {
        TextArea textArea = new TextArea();
        textArea.setFont(Font.font("Courier New"));
        textArea.setText(textAreaText);
        textArea.setWrapText(true);
        textArea.setEditable(true);
        Alert alert = new Alert(alertType);
        alert.setResizable(true);
        alert.getDialogPane().setMinHeight(400);
        alert.getDialogPane().setMinWidth(400);
        alert.setHeaderText(headerText);
        alert.getDialogPane().setContent(textArea);
        alert.setResizable(true);
        final Optional<ButtonType> buttonType = alert.showAndWait();
        if (buttonType.isPresent()) {
            if (buttonType.get() != ButtonType.OK) {
                return;
            }
        } else {
            return;
        }
    }*/
}
