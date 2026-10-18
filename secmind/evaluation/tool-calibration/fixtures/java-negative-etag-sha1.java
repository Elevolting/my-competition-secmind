import java.security.MessageDigest;

class EtagCalibration {
    byte[] makeETag(byte[] response) throws Exception {
        return MessageDigest.getInstance("SHA-1").digest(response);
    }
}
