package tools;

import javafx.scene.control.Alert;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Tools {

    public static void openInfoWindow(String title, String text){
        Alert alert = new Alert(Alert.AlertType.INFORMATION);
        alert.setTitle(title);
        alert.setHeaderText(null);
        alert.setContentText(text);
        alert.show();
    }

    public static byte[] hash(String password, String algorithm){
        try {
            byte[] inputBytes = Tools.stringToByteArray(password);

            MessageDigest digest = MessageDigest.getInstance(algorithm);

            return digest.digest(inputBytes);

        }catch (NoSuchAlgorithmException e){
            e.printStackTrace();
            return null;
        }
    }

    public static long countLines(File filename){
        InputStream is = null;
        try {
            is = new BufferedInputStream(new FileInputStream(filename.getAbsolutePath()));
            byte[] c = new byte[1024];

            int readChars = is.read(c);
            if (readChars == -1) return 0;

            long count = 0;
            while (readChars == 1024) {
                for (int i=0; i<1024;) {
                    if (c[i++] == '\n') {
                        ++count;
                    }
                }
                readChars = is.read(c);
            }

            while (readChars != -1) {
                for (int i=0; i<readChars; ++i) {
                    if (c[i] == '\n') {
                        ++count;
                    }
                }
                readChars = is.read(c);
            }

            return count == 0 ? 1 : count;
        } catch (Exception e){
            System.out.println(e);
            return 0;
        }
    }

    public static byte[] stringToByteArray(String string){
        return string.getBytes();
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    public static String byteArrayToString(byte[] byteArray){
        StringBuilder sb = new StringBuilder();
        for (byte b : byteArray)
            sb.append(String.format("%02x", b));

        return sb.toString();
    }

    public static String distinguishHash(String hash) {
        switch (hash.length()){
            case 32:
                return "MD5";
            case 40:
                return "SHA";
            case 56:
                return "SHA-224";
            case 64:
                return "SHA-256";
            case 96:
                return "SHA-384";
            case 128:
                return "SHA-512";
            default:
                return "Unknown hash";
        }
    }
}
