package default_package;

import java.util.Objects;

public class InfoVoto {

    private ElGamalCT xM;
    private ElGamalCT signedPreference;

    public InfoVoto(ElGamalCT xM, ElGamalCT signedPreference) {
        this.xM = xM;
        this.signedPreference = signedPreference;
    }

    public ElGamalCT getxM() {
        return xM;
    }

    public ElGamalCT getSignedPreference() {
        return signedPreference;
    }

    public void setxM(ElGamalCT xM) {
        this.xM = xM;
    }

    public void setSignedPreference(ElGamalCT signedPreference) {
        this.signedPreference = signedPreference;
    }

    @Override
    public int hashCode() {
        int hash = 5;
        hash = 97 * hash + Objects.hashCode(this.signedPreference);
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
        final InfoVoto other = (InfoVoto) obj;
        return Objects.equals(this.signedPreference, other.signedPreference);
    }

    @Override
    public String toString() {
        return "InfoVoto{" + "xM=" + xM + ", signedPreference=" + signedPreference + '}';
    }

}
