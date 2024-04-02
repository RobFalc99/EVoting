package default_package;

import java.math.BigInteger;
import java.security.Key;
import java.security.Security;
import java.util.ArrayList;
import java.util.HashMap;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey;

public class Tallier {

    private BigInteger skShare;
    private ElGamalSK centralServerSK;
    private ElGamalPK centralServerPK;
    private Key authenticatorPK;
    private BigInteger prime;
    private ArrayList<String> voti;
    private HashMap<String, Integer> tallierCount;
    private ArrayList<publicInfoVoto> publicTallierList;

    public Tallier(CentralServer centralServer, Key authenticatorPK) {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        this.voti = new ArrayList<>();
        this.tallierCount = new HashMap<>();
        this.publicTallierList = new ArrayList<>();
        this.centralServerPK = centralServer.getPk();
        this.prime = centralServer.getPrime();
        this.authenticatorPK = authenticatorPK;
        initCandidati();
    }

    public void initCandidati() {
        tallierCount.put("Carpentieri", 0);
        tallierCount.put("Casaburi", 0);
        tallierCount.put("Falcone", 0);
        tallierCount.put("Ferraioli", 0);
        tallierCount.put("Greco", 0);
    }
    
    public void publishTallierList(){
        System.out.println("========= TALLIER LIST =========");
        for (publicInfoVoto info : publicTallierList){
            System.out.println(info.getInfo().getSignedPreference() + " | " + info.getInfo().getxM() + " | " + info.getVoto() + " | " + info.getMotivo());
        }
    }

    public void setSkShare(BigInteger skShare) {
        this.skShare = skShare;
    }

    public void reconstructSecret(BigInteger[] secretshares) throws Exception {
        BigInteger accum = BigInteger.ZERO;
        BigInteger tmp = null;
        BigInteger value = null;
        for (int j = 0; j < secretshares.length; j++) {
            BigInteger numerator = BigInteger.ONE;
            BigInteger denominator = BigInteger.ONE;
            for (int i = 0; i < secretshares.length; i++) {
                if (j != i) {
                    int startposition = j + 1;
                    int nextposition = i + 1;

                    numerator = numerator.multiply(BigInteger.valueOf(nextposition).negate()).mod(prime); // (numerator * -nextposition) % prime;
                    denominator = denominator.multiply(BigInteger.valueOf(startposition - nextposition)).mod(prime); // (denominator * (startposition - nextposition)) % prime;
                }
            }
            value = secretshares[j];
            BigInteger di = numerator.multiply(denominator.modInverse(prime));
            tmp = value.multiply(di);
            accum = prime.add(accum).add(tmp).mod(prime); //  (prime + accum + (value * numerator * modInverse(denominator))) % prime;
        }

        this.centralServerSK = new ElGamalSK(accum, centralServerPK);
    }

    public Boolean verifySignedMessage(ElGamalCT signedMessage, ElGamalCT message) {
        BCRSAPublicKey pubKey = (BCRSAPublicKey) authenticatorPK;
        BigInteger modulus = pubKey.getModulus();
        BigInteger e = pubKey.getPublicExponent();

        BigInteger U = signedMessage.U;
        BigInteger V = signedMessage.V;
        BigInteger resultU = U.modPow(e, modulus);
        BigInteger resultV = V.modPow(e, modulus);

        ElGamalCT newCT = new ElGamalCT(resultV, resultU);

        return message.U.compareTo(newCT.U) == 0 && message.V.compareTo(newCT.V) == 0;
    }

    public ArrayList<String> decPreferences(ArrayList<InfoVoto> preferences) {
        for (InfoVoto voto : preferences) {

            ElGamalCT signedPreference = voto.getSignedPreference();
            ElGamalCT xM = voto.getxM();

            if (verifySignedMessage(signedPreference, xM)) {
                BigInteger plain = ElGamalUtils.Decrypt(xM, centralServerSK);
                String pref = new String(plain.toByteArray());
                if (!tallierCount.containsKey(pref)) {
                    publicTallierList.add(new publicInfoVoto(voto, true, "Candidato non valido", pref));
                } else {
                    publicTallierList.add(new publicInfoVoto(voto, false, "OK", pref));
                    voti.add(pref);
                }
            }

        }
        return voti;
    }

    public HashMap<String, Integer> countPreferences() {
        for (String voto : voti) {
            tallierCount.put(voto, tallierCount.get(voto) + 1);
        }
        return tallierCount;
    }

    private class publicInfoVoto {

        private InfoVoto info;
        private Boolean isScartato;
        private String motivo;
        private String voto;

        public publicInfoVoto(InfoVoto info, Boolean isScartato, String motivo, String voto) {
            this.info = info;
            this.isScartato = isScartato;
            this.motivo = motivo;
            this.voto = voto;
        }

        public InfoVoto getInfo() {
            return info;
        }

        public void setInfo(InfoVoto info) {
            this.info = info;
        }

        public Boolean getIsScartato() {
            return isScartato;
        }

        public void setIsScartato(Boolean isScartato) {
            this.isScartato = isScartato;
        }

        public String getMotivo() {
            return motivo;
        }

        public void setMotivo(String motivo) {
            this.motivo = motivo;
        }

        public String getVoto() {
            return voto;
        }

        public void setVoto(String voto) {
            this.voto = voto;
        }

        @Override
        public String toString() {
            return "publicInfoVoto{" + "info=" + info + ", isScartato=" + isScartato + ", motivo=" + motivo + ", voto=" + voto + '}';
        }

    }
}
