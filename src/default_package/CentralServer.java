package default_package;

import java.util.HashMap;
import static default_package.KeysUtils.generateElGamalKeys;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;

public class CentralServer {

    private final ElGamalPK pk;
    private final ElGamalSK sk;
    private HashMap<String, Integer> finalCount;
    private SecureRandom sc;
    private BigInteger prime;
    private HashMap<String, Integer> candidati;

    public CentralServer() {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        this.finalCount = new HashMap<>();
        this.sk = generateElGamalKeys(128);
        this.pk = this.sk.getPK();
        this.sc = new SecureRandom();
        this.candidati = new HashMap<>();
        initCandidati();
    }

    public void initCandidati() {
        candidati.put("Carpentieri", 0);
        candidati.put("Casaburi", 0);
        candidati.put("Falcone", 0);
        candidati.put("Ferraioli", 0);
        candidati.put("Greco", 0);
    }
    
    public void publishCentralServerList(){
        System.out.println("========= CENTRAL SERVER LIST =========");
        for (String s : candidati.keySet()) {
            System.out.println(s + " : " + candidati.get(s));
        }
    }

    public ElGamalPK getPk() {
        return pk;
    }

    public BigInteger getPrime() {
        return prime;
    }

    public BigInteger[] buildShares(int numberOfTalliers) {
        BigInteger[] secretshares = new BigInteger[numberOfTalliers];
        BigInteger elGamalSkInteger = this.sk.getX();
        this.prime = new BigInteger(elGamalSkInteger.bitLength() + 1, 256, sc);
        BigInteger[] coeff = new BigInteger[numberOfTalliers];
        coeff[0] = elGamalSkInteger;

        for (int i = 1; i < numberOfTalliers; i++) {
            BigInteger r;
            while (true) {
                r = new BigInteger(prime.bitLength(), sc);
                if (r.compareTo(BigInteger.ZERO) > 0 && r.compareTo(prime) < 0) {
                    break;
                }
            }
            coeff[i] = r;
        }

        for (int x = 1; x <= numberOfTalliers; x++) {
            BigInteger accum = elGamalSkInteger;

            for (int exp = 1; exp < numberOfTalliers; exp++) {
                accum = accum.add(coeff[exp].multiply(BigInteger.valueOf(x).pow(exp).mod(prime))).mod(prime);
            }
            secretshares[x - 1] = accum;
        }

        return secretshares;
    }

    public HashMap<String, Integer> finalCount(ArrayList<HashMap<String, Integer>> tallierLists) {

        for (HashMap<String, Integer> list : tallierLists) {
            for (String k : list.keySet()) {
                candidati.put(k, list.get(k) + candidati.get(k));
            }
        }

        return candidati;
    }

}
