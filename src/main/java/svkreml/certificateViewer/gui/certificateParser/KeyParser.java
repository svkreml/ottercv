package svkreml.certificateViewer.gui.certificateParser;


import org.bouncycastle.jcajce.provider.asymmetric.ecgost.BCECGOST3410PublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.ecgost12.BCECGOST3410_2012PublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;

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

public class KeyParser {

    public static KeyInfo getKeyInfo(PublicKey publicKey)
            throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException {
        String algorithm = publicKey.getAlgorithm();

        switch (algorithm) {
            case "RSA" -> {
                KeyFactory keyFact = KeyFactory.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
                RSAPublicKeySpec keySpec = keyFact.getKeySpec(publicKey, RSAPublicKeySpec.class);
                BigInteger modulus = keySpec.getModulus();
                BigInteger exponent = keySpec.getPublicExponent();
                if (exponent.intValue() < 0x10001) {
                    KeyInfo keyInfo = new KeyInfo(algorithm, modulus.toString(2).length(),
                            algorithm.toUpperCase() + modulus.toString(2).length());
                    keyInfo.setExponent(exponent);
                    return keyInfo;
                } else {
                    KeyInfo keyInfo = new KeyInfo(algorithm, modulus.toString(2).length(),
                            algorithm.toLowerCase() + modulus.toString(2).length());
                    keyInfo.setExponent(exponent);
                    return keyInfo;
                }

            }
            case "DSA" -> {
                KeyFactory keyFact = KeyFactory.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
                DSAPublicKeySpec keySpec = keyFact.getKeySpec(publicKey, DSAPublicKeySpec.class);
                BigInteger prime = keySpec.getP();
                return new KeyInfo(algorithm, prime.toString(2).length(),
                        algorithm.toUpperCase() + prime.toString(2).length());

            }
            case "EC" -> {
                ECPublicKey pubk = (ECPublicKey) publicKey;
                ECParameterSpec spec = pubk.getParams();
                int size = spec.getOrder().bitLength();
                if (spec instanceof ECNamedCurveSpec) {
                    return new KeyInfo(algorithm, size, ((ECNamedCurveSpec) spec).getName());
                }

            }
            case "ECGOST3410-2012" -> {
                BCECGOST3410_2012PublicKey pubk = (BCECGOST3410_2012PublicKey) publicKey;
                ECParameterSpec spec = pubk.getParams();
                int size = spec.getOrder().bitLength();
                if (spec instanceof ECNamedCurveSpec) {
                    return new KeyInfo(algorithm, size, ((ECNamedCurveSpec) spec).getName());
                } else {
                    return new KeyInfo(algorithm, size);
                }
            }
            case "ECGOST3410" -> {
                BCECGOST3410PublicKey pubk = (BCECGOST3410PublicKey) publicKey;
                ECParameterSpec spec = pubk.getParams();
                int size = spec.getOrder().bitLength();
                if (spec instanceof ECNamedCurveSpec) {
                    return new KeyInfo(algorithm, size, ((ECNamedCurveSpec) spec).getName());
                } else {
                    return new KeyInfo(algorithm, size);
                }
            }
        }
        return new KeyInfo(algorithm);
    }

    public static X509Certificate loadCertificate(byte[] asn1) throws CertificateException {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        InputStream in = new ByteArrayInputStream(asn1);
        return (X509Certificate) factory.generateCertificate(in);
    }
}
