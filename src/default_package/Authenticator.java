package default_package;

import default_package.exceptions.ElettoreNotLogged;
import default_package.exceptions.ElettoreAlreadySigned;
import static default_package.KeysUtils.generateRSAKeys;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Objects;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateKey;

public class Authenticator {

    private final Key publicKey;
    private final Key privateKey;
    private HashSet<InfoElettore> elettori;
    private HashSet<PublicInfoElettore> listAuthenticator;
    private static MessageDigest digest;
    private static String chrs = "0123456789abcdefghijklmnopqrstuvwxyz-_ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    public Authenticator() {
        this.elettori = new HashSet();
        this.listAuthenticator = new HashSet();
        KeyPair kp = generateRSAKeys(256);
        this.publicKey = kp.getPublic();
        this.privateKey = kp.getPrivate();
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException ex) {
            System.err.println(ex.getMessage());
        }
    }
    
    public void publishAuthenticatorList(){
        System.out.println("========= AUTHENTICATOR LIST =========");
        for (PublicInfoElettore info : listAuthenticator){
            System.out.println(info.getUserID() + " | " + info.getBlind() + " | " + info.getSignedBlind());
        }
    }

    public void printElettori() {
        for (InfoElettore e : elettori) {
            System.out.println(e);
        }
    }

    public Boolean isElettoreLogin(String userID, String password) throws ElettoreNotLogged {
        for (InfoElettore e : elettori) {
            if (e.getUserID().compareTo(userID) == 0 && password.length() == e.getRand().length()) {
                String rand = e.getRand();
                byte[] sha = e.getShaPassword();

                byte[] resultSha = shaPasswordGenerator(password, rand);

                return Arrays.toString(sha).compareTo(Arrays.toString(resultSha)) == 0;
            }
        }
        throw new ElettoreNotLogged("Elettore non presente nel database!");
    }

    public Boolean isElettoreSigned(String userID) {
        for (PublicInfoElettore e : listAuthenticator) {
            if (e.getUserID().compareTo(userID) == 0) {
                return true;
            }
        }
        return false;
    }

    public ElGamalCT signElettore(String userID, ElGamalCT blind) throws ElettoreAlreadySigned {
        if (!isElettoreSigned(userID)) {
            BCRSAPrivateKey privKey = (BCRSAPrivateKey) this.privateKey;
            BigInteger modulus = privKey.getModulus();
            BigInteger d = privKey.getPrivateExponent();

            BigInteger U = blind.U;
            BigInteger V = blind.V;
            BigInteger signedU = U.modPow(d, modulus);
            BigInteger signedV = V.modPow(d, modulus);

            ElGamalCT signedBlind = new ElGamalCT(signedV, signedU);

            listAuthenticator.add(new PublicInfoElettore(userID, blind, signedBlind));

            return signedBlind;
        } else {
            throw new ElettoreAlreadySigned("Elettore already signed!");
        }

    }

    private String generateSecureRandomString(int lenght) {
        SecureRandom r = null;

        try {
            r = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException ex) {
            System.err.println(ex.getMessage());
        }

        String randomString = r.ints(lenght, 0, chrs.length()).mapToObj(i -> chrs.charAt(i))
                .collect(StringBuilder::new, StringBuilder::append, StringBuilder::append).toString();
        return randomString;
    }

    private byte[] bytesArrayXor(byte[] array1, byte[] array2, int lenght) {
        byte[] xor = new byte[lenght];
        for (int i = 0; i < lenght; i++) {
            xor[i] = (byte) (array1[i] ^ array2[i]);
        }
        return xor;
    }

    private byte[] shaPasswordGenerator(String password, String rand) {
        byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_8);
        byte[] randBytes = rand.getBytes(StandardCharsets.UTF_8);

        byte[] xor = bytesArrayXor(passwordBytes, randBytes, password.length());

        return digest.digest(xor);
    }

    public void addElettore(String userID, String password) {
        String rand = generateSecureRandomString(password.length());
        byte[] shaPassword = shaPasswordGenerator(password, rand);

        elettori.add(new InfoElettore(userID, rand, shaPassword));
    }

    public void addPublicInfoElettore(String userID, ElGamalCT blind, ElGamalCT signedBlind) {
        listAuthenticator.add(new PublicInfoElettore(userID, blind, signedBlind));
    }

    public Key getPublicKey() {
        return publicKey;
    }

    private class InfoElettore {

        private String userID;
        private String rand;
        private byte[] shaPassword;

        public InfoElettore(String userID, String rand, byte[] shaPassword) {
            this.userID = userID;
            this.rand = rand;
            this.shaPassword = shaPassword;
        }

        public String getUserID() {
            return userID;
        }

        public void setUserID(String userID) {
            this.userID = userID;
        }

        public String getRand() {
            return rand;
        }

        public void setRand(String rand) {
            this.rand = rand;
        }

        public byte[] getShaPassword() {
            return shaPassword;
        }

        public void setShaPassword(byte[] shaPassword) {
            this.shaPassword = shaPassword;
        }

        @Override
        public int hashCode() {
            int hash = 7;
            hash = 59 * hash + Objects.hashCode(this.userID);
            return hash;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj == null) {
                return false;
            }
            if (getClass() != obj.getClass()) {
                return false;
            }
            final InfoElettore other = (InfoElettore) obj;
            return Objects.equals(this.userID, other.userID);
        }

        @Override
        public String toString() {
            return "InfoElettore{" + "userID=" + userID + ", rand=" + rand + ", shaPassword=" + shaPassword + '}';
        }

    }

    private class PublicInfoElettore {

        private String userID;
        private ElGamalCT blind;
        private ElGamalCT signedBlind;

        public PublicInfoElettore(String userID, ElGamalCT blind, ElGamalCT signedBlind) {
            this.userID = userID;
            this.blind = blind;
            this.signedBlind = signedBlind;
        }

        public String getUserID() {
            return userID;
        }

        public void setUserID(String userID) {
            this.userID = userID;
        }

        public ElGamalCT getBlind() {
            return blind;
        }

        public void setBlind(ElGamalCT blind) {
            this.blind = blind;
        }

        public ElGamalCT getSignedBlind() {
            return signedBlind;
        }

        public void setSignedBlind(ElGamalCT signedBlind) {
            this.signedBlind = signedBlind;
        }

        @Override
        public int hashCode() {
            int hash = 7;
            hash = 97 * hash + Objects.hashCode(this.userID);
            return hash;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj == null) {
                return false;
            }
            if (getClass() != obj.getClass()) {
                return false;
            }
            final PublicInfoElettore other = (PublicInfoElettore) obj;
            return Objects.equals(this.userID, other.userID);
        }

        @Override
        public String toString() {
            return "ListAuthenticator{" + "userID=" + userID + ", \nblind=" + blind + ", \nsignedBlind=" + signedBlind + '}';
        }

    }
}
