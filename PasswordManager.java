import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.Base64;
import java.security.SecureRandom;

public class PasswordManager {

    private static final String LOWER = "abcdefghijklmnopqrstuvwxyz";
    private static final String UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String DIGITS = "0123456789";
    private static final String SPECIAL = "!@#$%^&*()_-+=<>?/{}~|";
    private static final String ALL_CHARACTERS = LOWER + UPPER + DIGITS + SPECIAL;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String ALGORITHM = "AES";

    public static String generatePassword(int length) {
        if (length <= 0) {
            throw new IllegalArgumentException("Password length must be greater than zero");
        }

        StringBuilder password = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            password.append(ALL_CHARACTERS.charAt(RANDOM.nextInt(ALL_CHARACTERS.length())));
        }

        return password.toString();
    }

    public static SecretKey generateKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
        keyGen.init(256); // for AES-256
        return keyGen.generateKey();
    }

    public static String encrypt(String data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decrypt(String encryptedData, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedData);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        return new String(decryptedBytes);
    }

    public static void main(String[] args) {
        try {
            SecretKey key = generateKey();
            String password = generatePassword(12);
            System.out.println("Generated Password: " + password);

            String encryptedPassword = encrypt(password, key);
            System.out.println("Encrypted Password: " + encryptedPassword);

            String decryptedPassword = decrypt(encryptedPassword, key);
            System.out.println("Decrypted Password: " + decryptedPassword);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
