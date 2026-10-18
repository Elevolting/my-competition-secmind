import java.security.MessageDigest;

class ChecksumCalibration {
    byte[] checksum(byte[] content) throws Exception {
        return MessageDigest.getInstance("MD5").digest(content);
    }
}
