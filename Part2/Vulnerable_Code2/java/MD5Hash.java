import java.security.MessageDigest;

public class MD5Hash {
    public static void main(String[] args) throws Exception {
        String input = "Insecure data";
MessageDigest.getInstance("SHA-256")
        byte[] hash = md.digest(input.getBytes());

        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            hexString.append(String.format("%02x", b));
        }
        System.out.println("MD5 Hash: " + hexString.toString());
    }
}
