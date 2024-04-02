package default_package;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;

public class Anonymizer {

    private final ElGamalPK pk;
    private final ElGamalSK sk;
    private int position;
    private ArrayList<InfoVoto> anonSet;
    private ArrayList<ElGamalCT> decrypted;

    public Anonymizer(int position, int secureparameter) {
        this.sk = KeysUtils.generateElGamalKeys(secureparameter);
        this.pk = sk.getPK();
        this.position = position;
        this.anonSet = new ArrayList<>();
        this.decrypted = new ArrayList<>();
    }

    public ElGamalPK getPk() {
        return pk;
    }

    public ArrayList<ElGamalCT> getDecrypted() {
        return decrypted;
    }

    public ArrayList<InfoVoto> getAnonSet() {
        return anonSet;
    }
    
    public void decypher(ArrayList<ElGamalCT> ciphers) {
        ArrayList<ArrayList<ElGamalCT>> blocks = new ArrayList<>();
        if (position == 2) {
            for (int i = 0; i < ciphers.size(); i += 8) {
                ArrayList<ElGamalCT> tempList = new ArrayList<>();
                tempList.add(ciphers.get(i));
                tempList.add(ciphers.get(i + 1));
                tempList.add(ciphers.get(i + 2));
                tempList.add(ciphers.get(i + 3));
                tempList.add(ciphers.get(i + 4));
                tempList.add(ciphers.get(i + 5));
                tempList.add(ciphers.get(i + 6));
                tempList.add(ciphers.get(i + 7));
                blocks.add(tempList);
            }

            Collections.shuffle(blocks);

            for (ArrayList<ElGamalCT> block : blocks) {
                ElGamalCT newMessageUU = block.get(0);
                ElGamalCT newMessageUV = block.get(1);
                ElGamalCT newMessageVU = block.get(2);
                ElGamalCT newMessageVV = block.get(3);
                ElGamalCT newSignedUU = block.get(4);
                ElGamalCT newSignedUV = block.get(5);
                ElGamalCT newSignedVU = block.get(6);
                ElGamalCT newSignedVV = block.get(7);

                //DEC
                BigInteger decMessageUU = ElGamalUtils.Decrypt(newMessageUU, sk);
                BigInteger decMessageUV = ElGamalUtils.Decrypt(newMessageUV, sk);
                BigInteger decMessageVU = ElGamalUtils.Decrypt(newMessageVU, sk);
                BigInteger decMessageVV = ElGamalUtils.Decrypt(newMessageVV, sk);

                BigInteger decSignedUU = ElGamalUtils.Decrypt(newSignedUU, sk);
                BigInteger decSignedUV = ElGamalUtils.Decrypt(newSignedUV, sk);
                BigInteger decSignedVU = ElGamalUtils.Decrypt(newSignedVU, sk);
                BigInteger decSignedVV = ElGamalUtils.Decrypt(newSignedVV, sk);

                //RECONSTRUCT
                decrypted.add(new ElGamalCT(decMessageUV, decMessageUU)); //newMessageUf
                decrypted.add(new ElGamalCT(decMessageVV, decMessageVU)); //newMessageVf
                decrypted.add(new ElGamalCT(decSignedUV, decSignedUU)); //newSignedUf
                decrypted.add(new ElGamalCT(decSignedVV, decSignedVU)); //newSignedVf
            }

        } else if (position == 1) {

            for (int i = 0; i < ciphers.size(); i += 4) {
                ElGamalCT newMessageUf = ciphers.get(i);
                ElGamalCT newMessageVf = ciphers.get(i + 1);
                ElGamalCT newSignedUf = ciphers.get(i + 2);
                ElGamalCT newSignedVf = ciphers.get(i + 3);

                //DEC
                BigInteger decMessageU = ElGamalUtils.Decrypt(newMessageUf, sk);
                BigInteger decMessageV = ElGamalUtils.Decrypt(newMessageVf, sk);
                BigInteger decSignedU = ElGamalUtils.Decrypt(newSignedUf, sk);
                BigInteger decSignedV = ElGamalUtils.Decrypt(newSignedVf, sk);

                ElGamalCT messageFinal = new ElGamalCT(decMessageV, decMessageU);
                ElGamalCT signedFinal = new ElGamalCT(decSignedV, decSignedU);

                anonSet.add(new InfoVoto(messageFinal, signedFinal));
            }
            Collections.shuffle(anonSet);
        }

    }

}
