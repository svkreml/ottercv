package svkreml.certificateViewer.gui.certificateParser;



import java.math.BigInteger;


public class KeyInfo {
    public String getAlgorithm() {
        return algorithm;
    }

    public KeyInfo setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
        return this;
    }

    public Integer getSize() {
        return size;
    }

    public KeyInfo setSize(Integer size) {
        this.size = size;
        return this;
    }

    public BigInteger getModulus() {
        return modulus;
    }

    public KeyInfo setModulus(BigInteger modulus) {
        this.modulus = modulus;
        return this;
    }

    public BigInteger getExponent() {
        return exponent;
    }

    public KeyInfo setExponent(BigInteger exponent) {
        this.exponent = exponent;
        return this;
    }

    public String getDetailedAlgorithm() {
        return detailedAlgorithm;
    }

    public KeyInfo setDetailedAlgorithm(String detailedAlgorithm) {
        this.detailedAlgorithm = detailedAlgorithm;
        return this;
    }

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
