package default_package;

import java.util.ArrayList;

public class BulletinBoard {

    public ArrayList<ElGamalCT> preferences;

    public BulletinBoard() {
        this.preferences = new ArrayList<>();
    }

    public void addPreference(ArrayList<ElGamalCT> pref) {
        preferences.addAll(pref);
    }

    public ArrayList<ElGamalCT> getPreferences() {
        return preferences;
    }

}
