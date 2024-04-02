package default_package;

import java.math.BigInteger;

public class ElGamalCT {

    BigInteger V, U;

    public ElGamalCT(BigInteger V, BigInteger U) {
        this.V = V;
        this.U = U;

    }

    public ElGamalCT(ElGamalCT CT) {
        this.V = CT.V;
        this.U = CT.U;

    }

    @Override
    public String toString() {
        return "{" + "V=" + V + ", U=" + U + '}';
    }

}
