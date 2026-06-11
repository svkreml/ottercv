package svkreml.certificateViewer.gui.certificateParser;


import org.bouncycastle.jcajce.provider.asymmetric.ecgost.BCECGOST3410PublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.ecgost12.BCECGOST3410_2012PublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;

import lombok.extern.slf4j.Slf4j;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

@Slf4j
public class KeyParser {

    private static final int RSA_EXPONENT_THRESHOLD = 0x10001;
    private static final String ALGORITHM_RSA = "RSA";
    private static final String ALGORITHM_DSA = "DSA";
    private static final String ALGORITHM_EC = "EC";
    private static final String ALGORITHM_ECGOST_2012 = "ECGOST3410-2012";
    private static final String ALGORITHM_ECGOST = "ECGOST3410";
    private static final String X509_CERTIFICATE_TYPE = "X.509";

    public static KeyInfo getKeyInfo(PublicKey publicKey)
            throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException {
        String algorithm = publicKey.getAlgorithm();

        switch (algorithm) {
            case ALGORITHM_RSA -> {
                KeyFactory keyFact = KeyFactory.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
                RSAPublicKeySpec keySpec = keyFact.getKeySpec(publicKey, RSAPublicKeySpec.class);
                BigInteger modulus = keySpec.getModulus();
                BigInteger exponent = keySpec.getPublicExponent();
                String displayName = exponent.intValue() < RSA_EXPONENT_THRESHOLD
                        ? algorithm.toUpperCase() + modulus.toString(2).length()
                        : algorithm.toLowerCase() + modulus.toString(2).length();
                return KeyInfo.builder()
                        .algorithm(algorithm)
                        .size(modulus.toString(2).length())
                        .exponent(exponent)
                        .detailedAlgorithm(displayName)
                        .build();
            }
            case ALGORITHM_DSA -> {
                KeyFactory keyFact = KeyFactory.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
                DSAPublicKeySpec keySpec = keyFact.getKeySpec(publicKey, DSAPublicKeySpec.class);
                BigInteger prime = keySpec.getP();
                return KeyInfo.builder()
                        .algorithm(algorithm)
                        .size(prime.toString(2).length())
                        .detailedAlgorithm(algorithm.toUpperCase() + prime.toString(2).length())
                        .build();
            }
            case ALGORITHM_EC -> {
                var pubk = (ECPublicKey) publicKey;
                var spec = pubk.getParams();
                int size = spec.getOrder().bitLength();
                if (spec instanceof ECNamedCurveSpec namedSpec) {
                    return KeyInfo.builder()
                            .algorithm(algorithm)
                            .size(size)
                            .detailedAlgorithm(namedSpec.getName())
                            .build();
                }
            }
            case ALGORITHM_ECGOST_2012, ALGORITHM_ECGOST -> {
                int size;
                String curveName = null;
                if (publicKey instanceof BCECGOST3410_2012PublicKey gost12Key) {
                    var spec = gost12Key.getParams();
                    size = spec.getOrder().bitLength();
                    if (spec instanceof ECNamedCurveSpec namedSpec) {
                        curveName = namedSpec.getName();
                    }
                } else if (publicKey instanceof BCECGOST3410PublicKey gostKey) {
                    var spec = gostKey.getParams();
                    size = spec.getOrder().bitLength();
                    if (spec instanceof ECNamedCurveSpec namedSpec) {
                        curveName = namedSpec.getName();
                    }
                } else {
                    throw new IllegalArgumentException("Unsupported key type for " + algorithm);
                }
                var bob = KeyInfo.builder().algorithm(algorithm).size(size);
                if (curveName != null) bob.detailedAlgorithm(curveName);
                return bob.build();
            }
            default -> log.warn("Unknown key algorithm: {}", algorithm);
        }
        return KeyInfo.builder().algorithm(algorithm).detailedAlgorithm(algorithm).build();
    }

    public static X509Certificate loadCertificate(byte[] asn1) throws CertificateException {
        CertificateFactory factory = CertificateFactory.getInstance(X509_CERTIFICATE_TYPE);
        InputStream in = new ByteArrayInputStream(asn1);
        return (X509Certificate) factory.generateCertificate(in);
    }
}
