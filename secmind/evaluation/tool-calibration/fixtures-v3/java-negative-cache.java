import java.security.MessageDigest;

class CacheKeyV3 {
    byte[] makeKey(byte[] payload) throws Exception {
        return MessageDigest.getInstance("MD5").digest(payload);
    }
}
