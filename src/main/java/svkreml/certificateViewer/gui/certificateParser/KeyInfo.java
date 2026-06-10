package svkreml.certificateViewer.gui.certificateParser;


import lombok.Getter;
import lombok.Setter;

import java.math.BigInteger;



@Getter
@Setter
public class KeyInfo {
    private String algorithm;
    private Integer size;
    private BigInteger modulus;
    private BigInteger exponent;
    private String detailedAlgorithm;

    public KeyInfo(String algorithm) {
        this(algorithm, null, algorithm);
    }

    public KeyInfo(String algorithm, Integer size) {
        this.algorithm = algorithm;
        this.size = size;
        this.detailedAlgorithm = algorithm + size;
    }

    public KeyInfo(String algorithm, Integer size, String detailedAlgorithm) {
        this.algorithm = algorithm;
        this.size = size;
        this.detailedAlgorithm = detailedAlgorithm;
    }

}
