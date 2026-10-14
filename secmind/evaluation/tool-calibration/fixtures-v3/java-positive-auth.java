import java.security.MessageDigest;

class AuthLedgerV3 {
    void remember(String authToken) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("MD5");
        byte[] value = digest.digest(authToken.getBytes());
        secretStore.save(value);
    }
}
