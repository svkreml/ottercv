package svkreml.certificateViewer.gui.view.utils;

import javafx.geometry.Orientation;
import javafx.scene.Node;
import javafx.scene.control.Label;
import javafx.scene.control.Separator;
import javafx.scene.layout.AnchorPane;
import javafx.scene.layout.Pane;
import javafx.scene.text.TextAlignment;

public class FxUtils {
    public static void createLabel(Pane generalPane, String s, double top, double left) {
        Label label = new Label(s);
        label.setWrapText(true);
        label.setTextAlignment(TextAlignment.JUSTIFY);
        setAnchorPaneBorders(label, top, left, 30.0, null);
        generalPane.getChildren().add(label);
    }

    public static void createSeparator(Pane generalPane, double v) {
        Separator separator = new Separator();
        separator.setOrientation(Orientation.HORIZONTAL);
        setAnchorPaneBorders(separator, v, 30.0, 30.0, null);
        generalPane.getChildren().add(separator);
    }

    public static Node setAnchorPaneBorders(Node node, Double top, Double left, Double right, Double bottom) {
        AnchorPane.setTopAnchor(node, top);
        AnchorPane.setLeftAnchor(node, left);
        AnchorPane.setRightAnchor(node, right);
        AnchorPane.setBottomAnchor(node, bottom);
        return node;
    }
}
