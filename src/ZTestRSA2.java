import java.math.BigInteger;
import java.util.Scanner;

public class ZTestRSA2 {


    // Variable length key test
    // Note that if the key length is too small, could possibly generate exception (errors at 128, works for 256 and above)

    public static void main(String[] args) {
        Utility utility = new Utility();
        Scanner scanner = new Scanner(System.in);

        System.out.println("\nPlease specify the length of the RSA Key : ");
        int length = scanner.nextInt(); scanner.nextLine();
        utility.generateRSA(length);
        System.out.println("RSA Public Key = " + utility.getRsaPublicKey());
        System.out.println("RSA Modulus (p*q = N) = " + utility.getRsaModulus());

        System.out.println("\n Please type a message to encode : ");
        String str;
        str = scanner.nextLine();

        BigInteger bigInteger, bigInteger1;
        System.out.println("Message : " + str);

        bigInteger = utility.rsaEncrypt(str);
        System.out.println("RSA Encrypting : " + bigInteger);

        bigInteger1 = utility.rsaDecrypt(bigInteger);
        System.out.println("RSA Decrypting : " + bigInteger1);

        System.out.println("Decrypting the ASCII code in the BigInt : " + utility.decode(bigInteger1,utility.getMessagePosix()));

    }
}
