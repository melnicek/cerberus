package entity;

import java.io.Serializable;

// analyzed hash inherits everything from LoadedHash and add password variable
public class CrackedHash extends LoadedHash implements Serializable {

    private String password;

    // constructor
    public CrackedHash(String hexString, String algorithm, String password) {
        super(hexString, algorithm);
        this.password = password;
    }

    // getter setter
    public String getPassword() {
        return password;
    }
    public void setPassword(String password) {
        this.password = password;
    }
}
