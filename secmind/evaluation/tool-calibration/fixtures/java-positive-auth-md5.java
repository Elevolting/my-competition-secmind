import java.security.MessageDigest;

class AuthCalibration {
    void authenticate(String authToken) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("MD5");
        byte[] value = digest.digest(authToken.getBytes());
        sessionStore.save(value);
    }
}
