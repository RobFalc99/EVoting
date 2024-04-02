package default_package;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) throws Exception {
        ArrayList<HashMap<String, Integer>> finalMap = new ArrayList<>();
        HashMap<String, Integer> csCount;

        //Initializing system entites
        Authenticator auth = new Authenticator();

        BulletinBoard board = new BulletinBoard();

        Anonymizer anon1 = new Anonymizer(1, 256);
        Anonymizer anon2 = new Anonymizer(2, 512);

        CentralServer cs = new CentralServer();

        //Building central server shares
        BigInteger bg[] = cs.buildShares(2);

        Tallier t1 = new Tallier(cs, auth.getPublicKey());
        Tallier t2 = new Tallier(cs, auth.getPublicKey());

        //Sharing central server key
        t1.setSkShare(bg[0]);
        t2.setSkShare(bg[1]);

        //Adding some voters to the authenticator dataset
        auth.addElettore("rob_falc", "eugenioNapoli");
        auth.addElettore("carpe_eug", "robertoLewis");
        auth.addElettore("ado_cas", "semanos365");
        auth.addElettore("l.ferr", "cavese1919");

        //FIRST VOTER
        Elettore elettore1 = new Elettore("rob_falc", "eugenioNapoli");

        if (auth.isElettoreLogin(elettore1.getUserID(), elettore1.getPassword())) {
            ElGamalCT blind = elettore1.blindPreference("Carpentieri", cs.getPk(), auth.getPublicKey());
            ElGamalCT signed = auth.signElettore("rob_falc", blind);
            ElGamalCT signedPreference = elettore1.unblindPreference(signed, auth.getPublicKey());
            ArrayList<ElGamalCT> cryptedPref = elettore1.mixNetCipher(anon1, anon2);
            board.addPreference(cryptedPref);
        }

        //SECOND VOTER
        Elettore elettore2 = new Elettore("carpe_eug", "robertoLewis");

        if (auth.isElettoreLogin(elettore2.getUserID(), elettore2.getPassword())) {
            ElGamalCT blind2 = elettore2.blindPreference("Ferraioli", cs.getPk(), auth.getPublicKey());
            ElGamalCT signed2 = auth.signElettore("carpe_eug", blind2);
            ElGamalCT signedPreference2 = elettore2.unblindPreference(signed2, auth.getPublicKey());
            ArrayList<ElGamalCT> cryptedPref = elettore2.mixNetCipher(anon1, anon2);
            board.addPreference(cryptedPref);
        }

        //THIRD VOTER USER INPUT
        System.out.println("Welcome back sir!");
        Scanner scan = new Scanner(System.in);

        System.out.println("Insert userID: ");
        String userID = scan.next();

        System.out.println("Insert password: ");
        String password = scan.next();

        Elettore elettore3 = new Elettore(userID, password);

        if (auth.isElettoreLogin(userID, password)) {
            System.out.println("Insert preference: ");
            String pref = scan.next();

            //Applying blind factor on expressed preference
            ElGamalCT blind3 = elettore3.blindPreference(pref, cs.getPk(), auth.getPublicKey());
            //Requesting the Authenticator signature
            ElGamalCT signed3 = auth.signElettore(elettore3.getUserID(), blind3);
            //Unblind Authenticator signature
            ElGamalCT signedPreference3 = elettore3.unblindPreference(signed3, auth.getPublicKey());
            //Crypting the message to send to the Bulletin Board with the MixNet keys
            ArrayList<ElGamalCT> cryptedPref = elettore3.mixNetCipher(anon1, anon2);
            //Sending the vote and the unblinded Authenticator signature to the Bulletin Board
            board.addPreference(cryptedPref);
        } else {
            System.out.println("Wrong UserID or Password!");
        }
        
        //Publishing Authenticator list
        auth.publishAuthenticatorList();

        //Taking the votes list from the Bulletin Board
        ArrayList<ElGamalCT> finalPrefs = board.getPreferences();

        //MixNet decryption
        anon2.decypher(finalPrefs);
        ArrayList<ElGamalCT> intCryptedPref = anon2.getDecrypted();
        anon1.decypher(intCryptedPref);
        ArrayList<InfoVoto> finalInfoVoto = anon1.getAnonSet();

        //Reconstructing secret
        t1.reconstructSecret(bg);
        t2.reconstructSecret(bg);

        //Splitting the votes list among the Tallier servers
        ArrayList<InfoVoto> list1 = new ArrayList<>(finalInfoVoto.subList(0, 1));
        ArrayList<InfoVoto> list2 = new ArrayList<>(finalInfoVoto.subList(1, 3));

        //Decrypting and opening the votes
        t1.decPreferences(list1);
        t2.decPreferences(list2);

        //Partial counting from the Tallier servers
        finalMap.add(t1.countPreferences());
        finalMap.add(t2.countPreferences());
        
        //Publishing Tallier lists
        t1.publishTallierList();
        t2.publishTallierList();

        //Final counting from the Central Server
        csCount = cs.finalCount(finalMap);

        //Printing the results
        cs.publishCentralServerList();

        //Code to print the winner
        //System.out.println("Winner: " + Collections.max(csCount.entrySet(), Comparator.comparingInt(Map.Entry::getValue)).getKey());
    }

}
