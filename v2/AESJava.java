package v2;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Scanner;

public class AESJava {

    private static  String SECRET_KEY;

    private static String SALT;

    AESJava(String secretKey){
        SECRET_KEY = secretKey;
        SALT = secretKey;
    }

    public String encrypt(String strToEncrypt) {
        try {
            // Create default byte array
            byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            IvParameterSpec ivspec = new IvParameterSpec(iv);

            // Create SecretKeyFactory object
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");

            // Create KeySpec object and assign with
            // constructor
            KeySpec spec = new PBEKeySpec(SECRET_KEY.toCharArray(), SALT.getBytes(), 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
            // Return encrypted string
            return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {

        }
        return null;
    }

    public String decrypt(String strToDecrypt)
    {
        try {

            // Default byte array
            byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            // Create IvParameterSpec object and assign with
            // constructor
            IvParameterSpec ivspec = new IvParameterSpec(iv);

            // Create SecretKeyFactory Object
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");

            // Create KeySpec object and assign with
            // constructor
            KeySpec spec = new PBEKeySpec(SECRET_KEY.toCharArray(), SALT.getBytes(), 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);
            // Return decrypted string
            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
        }
        catch (Exception e) {

        }
        return null;
    }

    public static void main(String[] args){
        AESJava aesJava;
        Scanner sc = new Scanner(System. in);
        String secretKey = null;
        String operationType;
        String keyword = null;
        String encryptedWord = null;
        String decyptedKeyword = null;

        System.out.println("===============================================");
        System.out.print("Insert the secret key: ");
        secretKey = sc.nextLine();
        aesJava = new AESJava(secretKey);

        while(true){
            System.out.print("Enter the operation type (E: Encrypt, D: Decrypt, Anything: Exit): ");
            operationType = sc.nextLine();

            if(operationType.equals("E")){
                System.out.println("********************************************");
                System.out.print("Inserted the keyword to encrypt: ");
                keyword = sc.nextLine();
                System.out.println("Calling encrypting program .... (Please wait)");
                encryptedWord = aesJava.encrypt(keyword);
                System.out.println("Encrypted word: " + encryptedWord);
                System.out.println("********************************************");
            } else if (operationType.equals("D")){
                if(keyword != null){
                    decyptedKeyword = aesJava.decrypt(keyword);
                    System.out.println("********************************************");
                    System.out.print("Insert the encrypted: ");
                    keyword = sc.nextLine();
                    decyptedKeyword = aesJava.decrypt(keyword);
                    System.out.println("Decrypted keyword: " + decyptedKeyword);
                    System.out.println("********************************************");
                    keyword = null;
                    decyptedKeyword = null;
                } else {
                    System.out.println("NO encryption found!");
                    continue;
                }
            } else {
                System.out.println("Shutting down.. bye!");
                break;
            }
        }
    }
}
