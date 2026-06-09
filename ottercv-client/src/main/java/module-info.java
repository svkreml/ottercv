module svkreml.certificateViewer {
    requires javafx.controls;
    requires javafx.graphics;
    requires org.bouncycastle.provider;
    requires org.bouncycastle.pkix;
    requires java.naming;
    requires jakarta.xml.bind;
    opens svkreml.certificateViewer.gui.api.model;
    opens svkreml.tsl.tsl;
    exports svkreml.certificateViewer.gui;
}
