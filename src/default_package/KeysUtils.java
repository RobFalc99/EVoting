package default_package;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.logging.Level;
import java.util.logging.Logger;

public class KeysUtils {

    public static KeyPairGenerator RSAKeyPairGen;
    public static KeyPairGenerator elGamalKeyPairGenerator;

    public static KeyPair generateRSAKeys( int RSAKeyPairParams) {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        KeyPair rsaKeys = null;
        try {
            RSAKeyPairGen = KeyPairGenerator.getInstance("RSA", "BC");
            RSAKeyPairGen.initialize(RSAKeyPairParams);
            rsaKeys = RSAKeyPairGen.generateKeyPair();
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(KeysUtils.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchProviderException ex) {
            Logger.getLogger(KeysUtils.class.getName()).log(Level.SEVERE, null, ex);
        }

        return rsaKeys;
    }

    public static ElGamalSK generateElGamalKeys(int securityparameter) {
        BigInteger p, q, g, y;

        SecureRandom sc = new SecureRandom(); // create a secure random source

        while (true) {
            q = BigInteger.probablePrime(securityparameter, sc);

            // method probablePrime returns a prime number of length securityparameter
            // using sc as random source
            p = q.multiply(BigInteger.TWO);
            p = p.add(BigInteger.ONE);  // p=2q+1

            if (p.isProbablePrime(50) == true) {
                break;		// returns an integer that is prime with prob. 1-2^-50
            }
        }
        // henceforth we have that p and q are both prime numbers and p=2q+1
        // Subgroups of Zp* have order 2,q,2q
        g = new BigInteger("4"); // 4 is quadratic residue so it generates a group of order q
        // g is a generator of the subgroup the QR modulo p
        // in particular g generates q elements where q is prime

        BigInteger x = new BigInteger(securityparameter, sc); // x is the secret-key
        y = g.modPow(x, p); // y=g^x mod p

        ElGamalPK PK = new ElGamalPK(p, q, g, y, securityparameter);

        return new ElGamalSK(x, PK);

    }

}
