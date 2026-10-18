import java.security.MessageDigest;

class PasswordCalibration {
    byte[] hashPassword(String password) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("MD5");
        return digest.digest(password.getBytes());
    }
}
