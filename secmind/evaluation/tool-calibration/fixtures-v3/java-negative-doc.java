import java.security.MessageDigest;

class DocumentationDigestV3 {
    byte[] digest(String documentation) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("MD5");
        return digest.digest(documentation.getBytes());
    }
}
