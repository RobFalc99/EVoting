package default_package;

import java.math.BigInteger;

public class ElGamalPK {

    private final BigInteger g, y, p, q; // description of the group and public-key y=g^s
    int securityparameter; // security parameter

    public ElGamalPK(BigInteger p, BigInteger q, BigInteger g, BigInteger y, int securityparameter) {
        this.p = p;
        this.q = q;
        this.g = g;
        this.y = y;
        this.securityparameter = securityparameter;

    }

    public BigInteger getG() {
        return g;
    }

    public BigInteger getY() {
        return y;
    }

    public BigInteger getP() {
        return p;
    }

    public BigInteger getQ() {
        return q;
    }

    public int getSecurityparameter() {
        return securityparameter;
    }

}
