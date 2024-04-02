package default_package;

import java.math.BigInteger;
import java.security.SecureRandom;

public class ElGamalUtils {

    public static ElGamalCT Encrypt(ElGamalPK PK, BigInteger M) {
        SecureRandom sc = new SecureRandom(); // create a secure random source

        BigInteger r = new BigInteger(PK.securityparameter, sc); // choose random r of lenght security parameter
        // V=[y^r*M mod p, g^r mod p].

        BigInteger V = M.multiply(PK.getY().modPow(r, PK.getP())); // V=M*(y^r mod p)
        V = V.mod(PK.getP()); // V=V mod p
        BigInteger U = PK.getG().modPow(r, PK.getP());  // U=g^r mod p
        return new ElGamalCT(V, U);   // return CT=(V,U)

    }

    public static BigInteger Decrypt(ElGamalCT CT, ElGamalSK SK) {
        // V=[V,U]=[y^r*M mod p, g^r mod p].
        // y=g^x mod p

        BigInteger tmp = CT.U.modPow(SK.getX(), SK.getPK().getP());  // tmp=U^x mod p
        tmp = tmp.modInverse(SK.getPK().getP());
        // if tmp and p are BigInteger tmp.modInverse(p) is the integer x s.t. 
        // tmp*x=1 mod p
        // thus tmp=U^{-x}=g^{-rx} mod p =y^{-r}

        BigInteger M = tmp.multiply(CT.V).mod(SK.getPK().getP()); // M=tmp*V mod p
        return M;

    }

}
