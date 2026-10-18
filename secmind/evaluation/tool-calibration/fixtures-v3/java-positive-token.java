import java.security.MessageDigest;

class TokenVaultV3 {
    byte[] issueToken(String accessToken) throws Exception {
        return MessageDigest.getInstance("MD5").digest(accessToken.getBytes());
    }
}
