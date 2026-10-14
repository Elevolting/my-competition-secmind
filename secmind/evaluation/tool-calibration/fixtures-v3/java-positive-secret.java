import java.security.MessageDigest;

class SecretVaultV3 {
    byte[] seal(String serviceSecret) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-1");
        digest.update(serviceSecret.getBytes());
        return digest.digest();
    }
}
