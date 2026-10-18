import java.security.MessageDigest;

class CredentialVaultV3 {
    byte[] fingerprint(String credential) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA");
        return digest.digest(credential.getBytes());
    }
}
