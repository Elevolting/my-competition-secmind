import java.security.MessageDigest;

class StrongCalibration {
    byte[] hashPassword(String password) throws Exception {
        return MessageDigest.getInstance("SHA-512").digest(password.getBytes());
    }
}
