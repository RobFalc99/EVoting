package default_package;


import java.math.BigInteger;
//structures for ElGamal secret-key
//Vincenzo Iovino

public class ElGamalSK { // Secret-key of El Gamal

    private final BigInteger x;
    // x is random BigInteger from 1 to q where q is the order of g (g is in the PK)

    private final ElGamalPK PK; // PK of El Gamal

    public ElGamalSK(BigInteger x, ElGamalPK PK) {
        this.x = x;
        this.PK = PK;

    }

    public BigInteger getX() {
        return x;
    }

    public ElGamalPK getPK() {
        return PK;
    }
    
    
    
    
}
