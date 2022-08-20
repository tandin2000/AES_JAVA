import java.util.Scanner;

public class User {
    public static Scanner sc = new Scanner(System. in);
    public static void main(String[] args){
        String secretKey = null;
        String operationType;
        String keyword = null;
        String encryptedWord = null;
        String decyptedKeyword = null;
        while(true){
            System.out.println("Enter the operation type (E: Encrypt, D: Decrypt, Anything: Exit): ");
            operationType = sc.nextLine();
            if(operationType.equals("E")){
                System.out.println("********************************************");
                System.out.print("Inserted the Secret Key: ");
                secretKey = sc.nextLine();

                System.out.print("Inserted the keyword to encrypt: ");
                keyword = sc.nextLine();

                System.out.println("Calling encrypting program .... (Please wait)");
                Encrypter encrypter = new Encrypter(secretKey);

                encryptedWord = encrypter.encrypt(keyword);
                System.out.println("Encrypted word: " + encryptedWord);
                System.out.println("********************************************");

            } else if (operationType.equals("D")){
                if(keyword != null){
                    System.out.println("********************************************");
                    Decrypter decrypter = new Decrypter(secretKey);
                    System.out.print("Insert the encrypted: ");
                    keyword = sc.nextLine();
                    decyptedKeyword = decrypter.decrypt(keyword);
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
