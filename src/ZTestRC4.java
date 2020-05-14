import java.util.Arrays;
import java.util.Scanner;

public class ZTestRC4 {

    //  FIXED 1024 length key test

    public static void main(String[] args) {

        Utility utility = new Utility();
        utility.generateRC4();
        System.out.println("\n Automatically generated an RC4 instance with a 7-byte length key");
        System.out.println("RC4 Key = " + Arrays.toString(utility.defaultKey));

        System.out.println("\n Please type a message to encode : ");
        String str; Scanner scanner = new Scanner(System.in);
        str = scanner.nextLine();

        System.out.println("Message : " + str);
        System.out.println("Message bytes : " + Arrays.toString(str.getBytes()));

        byte[] bytes = utility.rc4Encrypt(str);
        System.out.println("RC4 Encrypting: " + Arrays.toString(bytes));

        byte[] bytes1 = utility.rc4Decrypt(bytes);
        System.out.println("RC4 Decrypting : " + Arrays.toString(bytes1));

        System.out.println("Message Decoding : " + new String(bytes1));

    }
}
