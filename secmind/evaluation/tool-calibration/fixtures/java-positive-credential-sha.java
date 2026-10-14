import java.security.MessageDigest;

class CredentialCalibration {
    byte[] authenticate(String credential) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA");
        return digest.digest(credential.getBytes());
    }
}
