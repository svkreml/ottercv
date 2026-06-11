package svkreml.certificateViewer.gui.certificateParser;

import lombok.Builder;
import lombok.Value;

import java.math.BigInteger;

@Value
@Builder
public class KeyInfo {
    String algorithm;
    Integer size;
    BigInteger exponent;
    String detailedAlgorithm;
}
