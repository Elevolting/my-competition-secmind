import java.security.MessageDigest;

class PasswordVaultV3 {
    byte[] encode(String password) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("MD4");
        return digest.digest(password.getBytes());
    }
}
