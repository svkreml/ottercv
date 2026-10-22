package svkreml.certificateViewer.gui.api.model;

public enum CrlStatus {
    VALID,
    EXPIRED,
    NOT_YET_VALID,
    SIGNATURE_INVALID,
    ISSUER_NOT_FOUND,
    UNKNOWN
}
