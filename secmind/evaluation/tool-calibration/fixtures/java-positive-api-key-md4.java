import java.security.MessageDigest;

class ApiKeyCalibration {
    byte[] signApiKey(String apiKey) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("MD4");
        return digest.digest(apiKey.getBytes());
    }
}
