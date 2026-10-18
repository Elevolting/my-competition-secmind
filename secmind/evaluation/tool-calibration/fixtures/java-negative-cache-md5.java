import java.security.MessageDigest;

class CacheCalibration {
    byte[] cacheKey(byte[] value) throws Exception {
        return MessageDigest.getInstance("MD5").digest(value);
    }
}
