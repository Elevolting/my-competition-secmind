import java.security.MessageDigest;

class ChecksumV3 {
    byte[] verify(byte[] artifact) throws Exception {
        return MessageDigest.getInstance("SHA-1").digest(artifact);
    }
}
