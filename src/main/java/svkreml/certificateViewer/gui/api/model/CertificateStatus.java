package svkreml.certificateViewer.gui.api.model;

public enum CertificateStatus {
    TRUSTED,
    UNTRUSTED_ROOT,
    UNTRUSTED_CHAIN,
    BROKEN,
    OVERDUE,
    UNKNOWN
}
