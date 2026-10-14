import java.security.MessageDigest;

class SecretCalibration {
    byte[] storeSecret(String secret) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-1");
        digest.update(secret.getBytes());
        return digest.digest();
    }
}
