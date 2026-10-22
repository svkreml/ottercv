package svkreml.certificateViewer.gui.view.tabs;

import javafx.geometry.Insets;
import javafx.scene.control.Tab;
import javafx.scene.control.TextArea;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import svkreml.certificateViewer.gui.localization.ru.Localization;

public class TabHelp {

    private static final String TEXT_FONT = "-fx-font-size: 12px;";

    private TabHelp() {
    }

    public static Tab create(Localization localization) {
        TextArea helpText = new TextArea(localization.helpText());
        helpText.setEditable(false);
        helpText.setWrapText(true);
        helpText.setStyle(TEXT_FONT);

        VBox root = new VBox(helpText);
        root.setPadding(new Insets(5.0));
        VBox.setVgrow(helpText, Priority.ALWAYS);

        Tab tab = new Tab(localization.TAB_HELP_TITLE, root);
        tab.setClosable(false);
        return tab;
    }
}
