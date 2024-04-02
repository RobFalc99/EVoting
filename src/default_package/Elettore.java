package default_package;

import default_package.exceptions.AuthenticatorSignatureFailure;
import java.math.BigInteger;
import java.security.Key;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey;

public class Elettore {

    private BigInteger randomS;
    private ElGamalCT blindedPreference;
    private ElGamalCT xM;
    private SecureRandom random;
    
    private String userID;
    private String password;

    private ElGamalCT signedPreference;

    public Elettore(String userID, String password) {
        try {
            this.random = SecureRandom.getInstanceStrong();
        } catch (Exception ex) {
            Logger.getLogger(Elettore.class.getName()).log(Level.SEVERE, null, ex);
        }
        this.userID = userID;
        this.password = password;
    }

    public String getUserID() {
        return userID;
    }

    public String getPassword() {
        return password;
    }

    public ElGamalCT getxM() {
        return xM;
    }

    public ElGamalCT getSignedPreference() {
        return signedPreference;
    }

    public ElGamalCT blindPreference(String preferenza, ElGamalPK pkCentralServer, Key pkAuthenticator) {
        BigInteger plainText = new BigInteger(preferenza.getBytes());

        //ELGAMAL
        ElGamalCT CT = ElGamalUtils.Encrypt(pkCentralServer, plainText);

        //BLIND
        BCRSAPublicKey pubKey = (BCRSAPublicKey) pkAuthenticator;
        BigInteger modulus = pubKey.getModulus();
        BigInteger e = pubKey.getPublicExponent();

        BigInteger s = new BigInteger(modulus.bitLength(), random);
        while (s.compareTo(modulus) >= 0) {
            s = new BigInteger(modulus.bitLength(), random);
        }

        this.randomS = s;

        this.xM = CT;

        BigInteger newU = (s.modPow(e, modulus).multiply(xM.U)).mod(modulus);
        BigInteger newV = (s.modPow(e, modulus).multiply(xM.V)).mod(modulus);

        ElGamalCT newCT = new ElGamalCT(newV, newU);

        this.blindedPreference = newCT;

        return blindedPreference;
    }

    public Boolean verifySignedBlind(ElGamalCT signedBlind, Key pkAuthenticator) {
        BCRSAPublicKey pubKey = (BCRSAPublicKey) pkAuthenticator;
        BigInteger modulus = pubKey.getModulus();
        BigInteger e = pubKey.getPublicExponent();

        BigInteger U = signedBlind.U;
        BigInteger V = signedBlind.V;
        BigInteger resultU = U.modPow(e, modulus);
        BigInteger resultV = V.modPow(e, modulus);

        ElGamalCT newCT = new ElGamalCT(resultV, resultU);

        return blindedPreference.U.compareTo(newCT.U) == 0 && blindedPreference.V.compareTo(newCT.V) == 0;
    }

    public ElGamalCT unblindPreference(ElGamalCT signedBlind, Key pkAuthenticator) throws AuthenticatorSignatureFailure {
        if (!verifySignedBlind(signedBlind, pkAuthenticator)) {
            throw new AuthenticatorSignatureFailure("The Authenticator' signature isn't valid!");
        }
        BCRSAPublicKey pubKey = (BCRSAPublicKey) pkAuthenticator;
        BigInteger modulus = pubKey.getModulus();
        BigInteger signedPreferenceU = randomS.modInverse(modulus).multiply(signedBlind.U).mod(modulus);
        BigInteger signedPreferenceV = randomS.modInverse(modulus).multiply(signedBlind.V).mod(modulus);

        this.signedPreference = new ElGamalCT(signedPreferenceV, signedPreferenceU);

        return signedPreference;
    }

    public ArrayList<ElGamalCT> mixNetCipher(Anonymizer anon1, Anonymizer anon2) {

        ArrayList<ElGamalCT> result = new ArrayList<>();

        ElGamalCT newMessageU = ElGamalUtils.Encrypt(anon1.getPk(), xM.U);
        ElGamalCT newMessageV = ElGamalUtils.Encrypt(anon1.getPk(), xM.V);
        ElGamalCT newSignedU = ElGamalUtils.Encrypt(anon1.getPk(), signedPreference.U);
        ElGamalCT newSignedV = ElGamalUtils.Encrypt(anon1.getPk(), signedPreference.V);

        //U MESSAGE
        result.add(ElGamalUtils.Encrypt(anon2.getPk(), newMessageU.U)); //newMessageUU
        result.add(ElGamalUtils.Encrypt(anon2.getPk(), newMessageU.V)); //newMessageUV
        //V MESSAGE
        result.add(ElGamalUtils.Encrypt(anon2.getPk(), newMessageV.U)); //newMessageVU
        result.add(ElGamalUtils.Encrypt(anon2.getPk(), newMessageV.V)); //newMessageVV

        //U SIGNED
        result.add(ElGamalUtils.Encrypt(anon2.getPk(), newSignedU.U)); //newSignedUU 
        result.add(ElGamalUtils.Encrypt(anon2.getPk(), newSignedU.V)); //newSignedUV
        //V SIGNED
        result.add(ElGamalUtils.Encrypt(anon2.getPk(), newSignedV.U)); //newSignedVU
        result.add(ElGamalUtils.Encrypt(anon2.getPk(), newSignedV.V)); //newSignedVV

        return result;

    }

}
